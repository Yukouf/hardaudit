#!/usr/bin/env python3
"""
HardAudit — Outil d'audit de securite pour VMs Linux.
Score sur 100, 8 modules, couleurs ANSI, export rapport.
Usage : sudo python3 hardaudit.py [--json | --quiet]
"""

import os, sys, re, pwd, grp, stat, socket, subprocess, json
from datetime import datetime
from collections import OrderedDict

# ─── COULEURS ────────────────────────────────────────────────────────────────
C = {"R": "\033[91m", "G": "\033[92m", "Y": "\033[93m", "B": "\033[94m",
     "W": "\033[97m", "D": "\033[90m", "E": "\033[0m", "BO": "\033[1m"}
if not sys.stdout.isatty():
    for k in C: C[k] = ""

class Finding:
    def __init__(self, title, detail, severity="MEDIUM"):
        self.title = title
        self.detail = detail
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.penalty = {"LOW": 1, "MEDIUM": 3, "HIGH": 5, "CRITICAL": 10}[severity]

class Module:
    def __init__(self, name, weight, ref=""):
        self.name = name
        self.weight = weight  # points max
        self.ref = ref        # ref CIS/ANSSI
        self.findings = []
        self.score = 0

    def add(self, title, detail, sev="MEDIUM"):
        self.findings.append(Finding(title, detail, sev))

    def finalize(self):
        penalty = sum(f.penalty for f in self.findings)
        self.score = max(0, self.weight - penalty)
        return self.score

# ─── MODULES D'AUDIT ─────────────────────────────────────────────────────────

def audit_users():
    m = Module("Utilisateurs & Authentification", 12, "CIS 5.x")
    if os.geteuid() != 0:
        m.add("Non-root", "Lancer avec sudo pour un audit complet.", "HIGH")
        return m

    # Root accessible ?
    try:
        pw = pwd.getpwnam("root")
        if pw.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            m.add("Root login actif", f"Shell root = {pw.pw_shell}. Desactiver le login root direct.", "HIGH")
    except: pass

    # Users avec UID 0 autre que root
    for p in pwd.getpwall():
        if p.pw_uid == 0 and p.pw_name != "root":
            m.add("UID 0 non-root", f"L'utilisateur '{p.pw_name}' a UID 0.", "CRITICAL")

    # Sudoers faibles
    try:
        sudoers = subprocess.run(["sudo", "-l", "-U", os.environ.get("SUDO_USER", "root")],
                                capture_output=True, text=True, timeout=5)
        if "(ALL) NOPASSWD: ALL" in sudoers.stdout:
            m.add("Sudo sans mot de passe", "NOPASSWD:ALL actif — toute commande sans authentification.", "HIGH")
    except: pass

    # Umask
    try:
        with open("/etc/login.defs") as f:
            for line in f:
                if line.startswith("UMASK"):
                    umask = line.split()[-1].strip()
                    if umask in ("022", "027"):
                        break
                    else:
                        m.add("UMASK faible", f"UMASK={umask} (attendu: 022 ou 027).", "LOW")
    except: pass

    # Mots de passe vides
    try:
        shadow = open("/etc/shadow").read()
        for line in shadow.splitlines():
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] in ("", "!", "*"):
                    continue
                if len(parts) >= 2 and parts[1] == "":
                    m.add("Mot de passe vide", f"L'utilisateur '{parts[0]}' n'a pas de mot de passe.", "CRITICAL")
    except: pass

    m.finalize()
    return m


def audit_ssh():
    m = Module("SSH", 12, "CIS 5.2 / ANSSI R5")
    sshd = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd):
        m.add("sshd_config absent", "SSH n'est pas installe ou config inaccessible.", "MEDIUM")
        m.finalize(); return m

    try:
        with open(sshd) as f:
            cfg = f.read()

        checks = {
            "PermitRootLogin": ("no", "HIGH", "Desactiver PermitRootLogin."),
            "PasswordAuthentication": ("no", "MEDIUM", "Utiliser uniquement des cles SSH."),
            "X11Forwarding": ("no", "LOW", "X11Forwarding expose l'affichage."),
            "MaxAuthTries": ("4", "LOW", "MaxAuthTries > 4 recommandé."),
            "ClientAliveInterval": ("300", "LOW", "Timeout idle recommande."),
            "Protocol": ("2", "MEDIUM", "Forcer SSH Protocol 2 uniquement."),
        }

        for key, (expected, sev, msg) in checks.items():
            found = re.search(rf"^\s*{key}\s+(.+)", cfg, re.MULTILINE)
            if not found:
                m.add(f"{key} non defini", msg, sev)
            else:
                val = found.group(1).split("#")[0].strip().lower()
                if val != expected.lower() and expected != "4":  # MaxAuthTries <= 4 OK
                    m.add(f"{key} = {val}", msg, sev)
                elif key == "MaxAuthTries" and int(val) > 6:
                    m.add(f"{key} = {val}", msg, sev)

        # Port par defaut
        port = re.search(r"^\s*Port\s+(\d+)", cfg, re.MULTILINE)
        if not port or port.group(1) == "22":
            m.add("Port SSH par defaut (22)", "Changer le port reduit le bruit des bots.", "LOW")
    except Exception as e:
        m.add("Erreur lecture SSH", str(e), "MEDIUM")

    m.finalize()
    return m


def audit_network():
    m = Module("Reseau & Ports", 12, "CIS 3.x")
    try:
        # Ports en ecoute
        listening = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        lines = [l for l in listening.stdout.splitlines() if "LISTEN" in l]

        # Ports exposes sur 0.0.0.0
        exposed = [l for l in lines if "0.0.0.0:" in l or "*:" in l]
        known_ok = {"22", "80", "443", "4173", "11434", "5000", "3000", "8080", "8443",
                     "53", "9377", "20241", "20242", "20243"}  # ports dev/DNS connus
        seen = set()
        for line in exposed:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                port = addr.split(":")[-1]
                if port in seen: continue
                seen.add(port)
                if port not in known_ok:
                    m.add(f"Port {port} expose", f"Service en ecoute sur 0.0.0.0:{port}.", "MEDIUM")

        # IPv6 si pas utilise
        if os.path.exists("/proc/net/if_inet6"):
            with open("/proc/net/if_inet6") as f:
                if f.read().strip():
                    # Verifier si IPv6 est desactive
                    disable_ipv6 = os.path.exists("/etc/sysctl.d/99-disable-ipv6.conf")
                    if not disable_ipv6:
                        m.add("IPv6 actif", "Desactiver si non utilise.", "LOW")
    except Exception as e:
        m.add("Erreur audit reseau", str(e), "MEDIUM")

    m.finalize()
    return m


def audit_firewall():
    m = Module("Firewall", 12, "CIS 3.5")
    try:
        # iptables
        ipt = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5)
        nft = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=5)
        ufw = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)

        has_ipt = len([l for l in ipt.stdout.splitlines() if l.strip() and not l.startswith("Chain")]) > 0
        has_nft = "table" in nft.stdout.lower()
        has_ufw = "active" in ufw.stdout.lower()

        if not (has_ipt or has_nft or has_ufw):
            m.add("Aucun firewall actif", "Ni iptables, ni nftables, ni UFW detecte.", "CRITICAL")
        else:
            # Verifier politique par defaut DROP
            if has_ipt:
                for line in ipt.stdout.splitlines():
                    if line.startswith("Chain INPUT") and "DROP" not in line:
                        m.add("Politique INPUT != DROP", "iptables INPUT policy n'est pas DROP.", "HIGH")
                        break
    except: pass
    m.finalize()
    return m


def audit_updates():
    m = Module("Mises a jour", 10, "CIS 1.8 / ANSSI R3")
    try:
        # Compter les updates dispo
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=10)
        updates = [l for l in result.stdout.splitlines() if "/" in l and "Listing" not in l]
        n = len(updates)

        if n > 50:
            m.add(f"{n} mises a jour dispo", "Systeme critique — mettre a jour d'urgence.", "CRITICAL")
        elif n > 20:
            m.add(f"{n} mises a jour dispo", "Plus de 20 paquets a mettre a jour.", "HIGH")
        elif n > 5:
            m.add(f"{n} mises a jour dispo", "Paquets a mettre a jour.", "MEDIUM")

        # Unattended-upgrades
        if not os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades"):
            m.add("unattended-upgrades absent", "Installer pour les mises a jour de securite auto.", "MEDIUM")
    except: pass
    m.finalize()
    return m


def audit_kernel():
    m = Module("Kernel & Protections", 14, "CIS 1.6 / ANSSI R14")
    checks = {
        "/proc/sys/kernel/randomize_va_space": ("2", "ASLR desactive", "CRITICAL"),
        "/proc/sys/kernel/kptr_restrict": ("1", "kptr_restrict < 1", "MEDIUM"),
        "/proc/sys/kernel/dmesg_restrict": ("1", "dmesg accessible", "LOW"),
        "/proc/sys/kernel/yama/ptrace_scope": ("1", "ptrace non restreint", "MEDIUM"),
        "/proc/sys/net/ipv4/tcp_syncookies": ("1", "TCP syncookies off", "MEDIUM"),
        "/proc/sys/net/ipv4/ip_forward": ("0", "IP forwarding actif", "MEDIUM"),
        "/proc/sys/net/ipv4/conf/all/accept_source_route": ("0", "Source routing accepte", "HIGH"),
        "/proc/sys/net/ipv4/conf/all/accept_redirects": ("0", "ICMP redirects acceptes", "MEDIUM"),
        "/proc/sys/net/ipv4/conf/all/send_redirects": ("0", "ICMP redirects envoyes", "LOW"),
        "/proc/sys/fs/suid_dumpable": ("0", "Core dumps SUID actifs", "MEDIUM"),
    }

    for path, (expected, msg, sev) in checks.items():
        try:
            with open(path) as f:
                val = f.read().strip()
            if val != expected:
                m.add(msg, f"{path} = {val} (attendu: {expected})", sev)
        except: pass

    # Kernel version
    try:
        uname = os.uname()
        major, minor = map(int, uname.release.split(".")[:2])
        if major < 5 or (major == 5 and minor < 10):
            m.add("Kernel obsolete", f"{uname.release} — passer a 5.10+ ou 6.x.", "HIGH")
    except: pass

    m.finalize()
    return m


def audit_services():
    m = Module("Services & Cron", 10, "CIS 2.x")
    try:
        # Services suspects
        suspicious = ["telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd"]
        for svc in suspicious:
            r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, timeout=3)
            if r.returncode == 0:
                m.add(f"Service obsolete: {svc}", f"Le service {svc} est actif — desactiver.", "HIGH")

        # Cron jobs world-writable
        cron_dirs = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/var/spool/cron/crontabs"]
        for cron_dir in cron_dirs:
            if not os.path.exists(cron_dir): continue
            for f in os.listdir(cron_dir):
                fp = os.path.join(cron_dir, f)
                try:
                    if os.stat(fp).st_mode & 0o022:
                        m.add(f"Cron writable: {fp}", "Fichier cron accessible en ecriture a d'autres.", "HIGH")
                except: pass
    except: pass
    m.finalize()
    return m


def audit_filesystem():
    m = Module("Systeme de fichiers", 10, "CIS 1.1 / ANSSI R28")
    try:
        # /tmp executable
        tmp_opts = subprocess.run(["findmnt", "/tmp", "-o", "OPTIONS", "-n"],
                                 capture_output=True, text=True, timeout=3)
        if "noexec" not in tmp_opts.stdout:
            m.add("/tmp executable", "Monter /tmp avec noexec,nosuid.", "MEDIUM")

        # World-writable files (echantillon rapide)
        r = subprocess.run(["find", "/etc", "-type", "f", "-perm", "-o+w", "-maxdepth", "2"],
                          capture_output=True, text=True, timeout=5)
        writable = [l for l in r.stdout.splitlines() if l.strip()]
        if writable:
            m.add(f"{len(writable)} fichiers world-writable dans /etc",
                  "Verifier les permissions (ex: shadow, passwd).", "HIGH")

        # Sticky bit sur /tmp
        tmp_stat = os.stat("/tmp")
        if not (tmp_stat.st_mode & stat.S_ISVTX):
            m.add("Sticky bit absent sur /tmp", "chmod +t /tmp", "HIGH")

        # /etc/shadow permissions
        try:
            shadow_stat = os.stat("/etc/shadow")
            if shadow_stat.st_mode & 0o077:
                m.add("/etc/shadow lisible", "Permissions trop larges sur /etc/shadow.", "CRITICAL")
        except: pass

    except Exception as e:
        m.add("Erreur audit FS", str(e), "MEDIUM")

    m.finalize()
    return m


def audit_logs():
    m = Module("Logs & Monitoring", 8, "CIS 4.x")
    try:
        if not os.path.exists("/etc/audit/auditd.conf"):
            m.add("auditd absent", "Installer auditd pour tracer les evenements securite.", "MEDIUM")

        # rsyslog
        r = subprocess.run(["systemctl", "is-active", "rsyslog"], capture_output=True, timeout=3)
        if r.returncode != 0:
            r2 = subprocess.run(["systemctl", "is-active", "syslog-ng"], capture_output=True, timeout=3)
            if r2.returncode != 0:
                m.add("Pas de syslog actif", "Ni rsyslog, ni syslog-ng ne tournent.", "HIGH")

        # logrotate
        if not os.path.exists("/etc/logrotate.conf"):
            m.add("logrotate absent", "Les logs peuvent saturer le disque.", "LOW")
    except: pass
    m.finalize()
    return m


# ─── AFFICHAGE ───────────────────────────────────────────────────────────────

def banner():
    print(f"""{C['G']}
 ╔══════════════════════════════════════════════════════════╗
 ║  {C['BO']}██╗  ██╗ █████╗ ██████╗ ██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗{C['G']}  ║
 ║  {C['BO']}██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝{C['G']}  ║
 ║  {C['BO']}███████║███████║██████╔╝██║  ██║███████║██║   ██║██║  ██║██║   ██║   {C['G']}  ║
 ║  {C['BO']}██╔══██║██╔══██║██╔══██╗██║  ██║██╔══██║██║   ██║██║  ██║██║   ██║   {C['G']}  ║
 ║  {C['BO']}██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║   {C['G']}  ║
 ║  {C['BO']}╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   {C['G']}  ║
 ║                                                          ║
 ║     Audit de securite Linux — rapide, visuel, actionnable ║
 ╚══════════════════════════════════════════════════════════╝{C['E']}
""")

def print_header(module, score, max_score):
    pct = int(score / max_score * 100) if max_score > 0 else 0
    col = C['G'] if pct >= 80 else C['Y'] if pct >= 50 else C['R']
    print(f"\n{C['BO']}  [{col}{score}/{max_score}{C['E']}{C['BO']}] {module.name}{C['E']}  {C['D']}{module.ref}{C['E']}")

def print_finding(f, idx):
    icon = {"LOW": "i", "MEDIUM": "⚠", "HIGH": "▲", "CRITICAL": "☠"}
    col = {"LOW": C['B'], "MEDIUM": C['Y'], "HIGH": C['R'], "CRITICAL": C['R']+C['BO']}
    ico = icon.get(f.severity, "!")
    cc = col.get(f.severity, C['W'])
    print(f"  {cc}{ico} [{f.severity:8s}] {f.title}{C['E']}")
    print(f"     {C['D']}{f.detail}{C['E']}")

def print_summary(modules):
    total = sum(m.score for m in modules)
    max_total = sum(m.weight for m in modules)
    pct = int(total / max_total * 100) if max_total > 0 else 0

    col = C['G'] if pct >= 80 else C['Y'] if pct >= 50 else C['R']
    grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"

    print(f"\n{C['BO']}╔══════════════════════════════════════════╗{C['E']}")
    print(f"{C['BO']}║  SCORE FINAL : {col}{total}/{max_total} — {pct}% — GRADE {grade}  {C['BO']}║{C['E']}")
    print(f"{C['BO']}╚══════════════════════════════════════════╝{C['E']}")

    print(f"\n{C['BO']}  Recapitulatif :{C['E']}")
    for m in modules:
        pct_m = int(m.score / m.weight * 100) if m.weight > 0 else 0
        col_m = C['G'] if pct_m >= 80 else C['Y'] if pct_m >= 50 else C['R']
        bar = "█" * (pct_m // 10) + "░" * (10 - pct_m // 10)
        findings = sum(1 for f in m.findings if f.severity in ("HIGH", "CRITICAL"))
        warn = f"{C['R']}⚠{findings}{C['E']}" if findings > 0 else f"{C['G']}✓{C['E']}"
        print(f"  {col_m}{bar}{C['E']} {m.name:<35} {col_m}{m.score}/{m.weight}{C['E']} {warn}")

    print(f"\n{C['D']}  Audite le {datetime.now().strftime('%d/%m/%Y a %H:%M:%S')} sur {socket.gethostname()}{C['E']}\n")

    # Recommandations prioritaires
    criticals = [f for m in modules for f in m.findings if f.severity == "CRITICAL"]
    highs = [f for m in modules for f in m.findings if f.severity == "HIGH"]
    if criticals or highs:
        print(f"{C['BO']}{C['R']}  ACTIONS PRIORITAIRES :{C['E']}")
        for f in criticals[:3]:
            print(f"  {C['R']}☠{C['E']} {f.title}")
        for f in highs[:3]:
            print(f"  {C['R']}▲{C['E']} {f.title}")
        print()


def export_report(modules, filepath):
    total = sum(m.score for m in modules)
    max_total = sum(m.weight for m in modules)
    pct = int(total / max_total * 100)

    lines = []
    lines.append(f"=== RAPPORT D'AUDIT HARD AUDIT ===")
    lines.append(f"Date : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    lines.append(f"Host : {socket.gethostname()}")
    lines.append(f"Score : {total}/{max_total} ({pct}%)")
    lines.append("")

    for m in modules:
        lines.append(f"[{m.score}/{m.weight}] {m.name} — {m.ref}")
        for f in m.findings:
            lines.append(f"  [{f.severity}] {f.title}")
            lines.append(f"         {f.detail}")
        lines.append("")

    lines.append("=== FIN DU RAPPORT ===")
    with open(filepath, "w") as f:
        f.write("\n".join(lines))
    return filepath


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HardAudit — Audit de securite VM Linux")
    parser.add_argument("--json", action="store_true", help="Sortie JSON")
    parser.add_argument("--quiet", action="store_true", help="Score uniquement")
    parser.add_argument("-o", "--output", help="Export rapport TXT")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.quiet:
        print(f"{C['Y']}[!] Lance avec sudo pour un audit complet.{C['E']}")

    modules = [
        audit_users(),
        audit_ssh(),
        audit_network(),
        audit_firewall(),
        audit_updates(),
        audit_kernel(),
        audit_services(),
        audit_filesystem(),
        audit_logs(),
    ]

    if args.json:
        data = {
            "host": socket.gethostname(),
            "date": datetime.now().isoformat(),
            "score": sum(m.score for m in modules),
            "max": sum(m.weight for m in modules),
            "modules": [{"name": m.name, "score": m.score, "max": m.weight,
                         "findings": [{"title": f.title, "severity": f.severity, "detail": f.detail}
                                      for f in m.findings]} for m in modules]
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if not args.quiet:
        banner()

    for m in modules:
        if not args.quiet:
            print_header(m, m.score, m.weight)
            for i, f in enumerate(m.findings):
                print_finding(f, i)
            if not m.findings:
                print(f"  {C['G']}✓ Aucune anomalie detectee{C['E']}")

    if not args.quiet:
        print_summary(modules)

    # Export rapport
    if args.output:
        path = export_report(modules, args.output)
        print(f"{C['G']}[✓] Rapport exporte : {path}{C['E']}")

    # Code de sortie
    total = sum(m.score for m in modules)
    max_total = sum(m.weight for m in modules)
    pct = int(total / max_total * 100)
    sys.exit(0 if pct >= 80 else 1)


if __name__ == "__main__":
    main()
