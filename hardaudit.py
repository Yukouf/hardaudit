#!/usr/bin/env python3
"""
HardAudit — Outil d'audit de securite pour VMs Linux.
Score sur 100, 9 modules, couleurs ANSI, export rapport.
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
    def __init__(self, title, detail, severity="MEDIUM", verify=""):
        self.title = title
        self.detail = detail
        self.severity = severity  # INFO, LOW, MEDIUM, HIGH, CRITICAL
        self.verify = verify
        self.penalty = {"INFO": 0, "LOW": 1, "MEDIUM": 3, "HIGH": 5, "CRITICAL": 10}[severity]

class Module:
    def __init__(self, name, weight, ref=""):
        self.name = name
        self.weight = weight  # points max
        self.ref = ref        # ref CIS/ANSSI
        self.findings = []
        self.score = 0

    def add(self, title, detail, sev="MEDIUM", verify=""):
        self.findings.append(Finding(title, detail, sev, verify))

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

    # Le shell de root ne prouve pas que root peut se connecter a distance.
    # Ce risque est controle dans le module SSH via PermitRootLogin.

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
        with open("/etc/shadow") as f:
            shadow = f.read()
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


def get_effective_sshd_settings(config_path="/etc/ssh/sshd_config"):
    """Lit la configuration SSH effective, y compris valeurs par defaut et Include."""
    try:
        result = subprocess.run(
            ["sshd", "-T", "-f", config_path],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return {
                line.split(None, 1)[0].lower(): line.split(None, 1)[1].strip().lower()
                for line in result.stdout.splitlines() if len(line.split(None, 1)) == 2
            }
    except (OSError, subprocess.SubprocessError):
        pass

    # Repli limite : directives explicites du fichier principal seulement.
    settings = {}
    try:
        with open(config_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() not in settings:
                    settings[parts[0].lower()] = parts[1].strip().lower()
    except OSError:
        pass
    return settings


def audit_ssh():
    m = Module("SSH", 12, "CIS 5.2 / ANSSI R5")
    sshd = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd):
        m.add("sshd_config absent", "SSH n'est pas installe ou config inaccessible.", "MEDIUM")
        m.finalize(); return m

    settings = get_effective_sshd_settings(sshd)
    verify = "sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|clientaliveinterval) '"
    if not settings:
        m.add("Configuration SSH effective inaccessible", "Impossible d'executer sshd -T ou de lire la configuration.", "MEDIUM", verify)
        m.finalize(); return m

    permit_root = settings.get("permitrootlogin")
    if permit_root != "no":
        m.add(
            f"PermitRootLogin effectif = {permit_root or 'inconnu'}",
            "La configuration effective autorise encore root directement, au moins par cle.",
            "HIGH" if permit_root == "yes" else "MEDIUM", verify,
        )

    password_auth = settings.get("passwordauthentication")
    if password_auth != "no":
        m.add(
            f"PasswordAuthentication effectif = {password_auth or 'inconnu'}",
            "Les mots de passe SSH restent autorises par la configuration effective.",
            "MEDIUM", verify,
        )

    if settings.get("x11forwarding") != "no":
        m.add("X11Forwarding actif", "Desactiver si le transfert d'affichage n'est pas utilise.", "LOW", verify)

    try:
        max_auth = int(settings.get("maxauthtries", "6"))
        if max_auth > 4:
            m.add(f"MaxAuthTries effectif = {max_auth}", "Limiter a 4 essais ou moins.", "LOW", verify)
    except ValueError:
        m.add("MaxAuthTries invalide", "Valeur effective non numerique.", "LOW", verify)

    try:
        idle = int(settings.get("clientaliveinterval", "0"))
        if idle == 0 or idle > 300:
            m.add(f"ClientAliveInterval effectif = {idle}", "Configurer un delai de session inactive entre 1 et 300 secondes.", "LOW", verify)
    except ValueError:
        m.add("ClientAliveInterval invalide", "Valeur effective non numerique.", "LOW", verify)

    m.finalize()
    return m


def extract_unreviewed_wildcard_ports(output):
    """Retourne les ports liés à toutes les interfaces sans prétendre qu'ils sont publics."""
    common_public = {"22", "80", "443"}
    ports = set()
    pattern = re.compile(r"(?:0\.0\.0\.0|\*|\[::\]):(\d+)")
    for line in output.splitlines():
        if "LISTEN" not in line.upper():
            continue
        for port in pattern.findall(line):
            if port not in common_public:
                ports.add(port)
    return sorted(ports, key=lambda value: int(value))


def firewall_has_default_deny(iptables_text, nft_text, ufw_text):
    """Détecte une politique entrante deny/drop dans le backend réellement actif."""
    if re.search(r"(?mi)^Status:\s*active\s*$", ufw_text) and re.search(
        r"(?mi)^Default:\s*(?:deny|reject)\s*\(incoming\)", ufw_text
    ):
        return True
    if re.search(r"(?mi)^(?:Chain INPUT \(policy|-P INPUT\s+)(?:DROP|REJECT)\)?", iptables_text):
        return True
    if re.search(r"(?is)hook\s+input[^}]*policy\s+(?:drop|reject)\s*;", nft_text):
        return True
    return False


def _capture(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        return result.returncode, result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def audit_network(allowed_ports=None):
    m = Module("Reseau & Ports", 12, "CIS 3.x")
    allowed_ports = {str(port) for port in (allowed_ports or set())}
    try:
        # Une écoute wildcard est un fait local. L'exposition externe dépend du firewall.
        code, output = _capture(["ss", "-tlnp"])
        if code != 0:
            _, output = _capture(["netstat", "-tlnp"])
        ports = extract_unreviewed_wildcard_ports(output)
        unreviewed = [port for port in ports if port not in allowed_ports]
        expected = [port for port in ports if port in allowed_ports]
        if unreviewed:
            listed = ", ".join(unreviewed)
            m.add(
                f"{len(unreviewed)} port(s) en ecoute sur toutes les interfaces",
                f"Ports: {listed}. Cela ne prouve pas une accessibilite depuis Internet ; verifier le firewall et les besoins metier.",
                "MEDIUM",
                verify="sudo ss -ltnp; sudo ufw status verbose; sudo nft list ruleset",
            )
        if expected:
            m.add(
                f"{len(expected)} port(s) attendu(s) selon le contexte fourni",
                f"Ports: {', '.join(expected)}. Ils restent affiches pour la tracabilite mais ne reduisent pas le score.",
                "INFO",
                verify="sudo ss -ltnp",
            )
    except Exception as e:
        m.add("Erreur audit reseau", str(e), "MEDIUM")

    m.finalize()
    return m


def audit_firewall():
    m = Module("Firewall", 12, "CIS 3.5")
    try:
        _, ipt = _capture(["iptables", "-L", "-n"])
        _, nft = _capture(["nft", "list", "ruleset"])
        _, ufw = _capture(["ufw", "status", "verbose"])

        has_ipt = bool(re.search(r"(?m)^Chain\s+", ipt))
        has_nft = "table" in nft.lower()
        has_ufw = bool(re.search(r"(?mi)^Status:\s*active\s*$", ufw))

        verify = "sudo ufw status verbose; sudo nft list ruleset; sudo iptables -S INPUT"
        if not (has_ipt or has_nft or has_ufw):
            m.add("Aucun firewall actif", "Ni iptables, ni nftables, ni UFW actif detecte.", "CRITICAL", verify)
        elif not firewall_has_default_deny(ipt, nft, ufw):
            m.add(
                "Politique entrante par defaut non bloquante",
                "Aucune politique deny/drop entrante n'a ete identifiee dans UFW, nftables ou iptables. Les regles detaillees restent a examiner.",
                "MEDIUM",
                verify,
            )
    except Exception as e:
        m.add("Erreur audit firewall", str(e), "MEDIUM")
    m.finalize()
    return m


def classify_update_severity(total, security):
    if security > 20:
        return "CRITICAL"
    if security > 0 or total > 20:
        return "HIGH"
    if total > 5:
        return "MEDIUM"
    return "LOW"


def audit_updates():
    m = Module("Mises a jour", 10, "CIS 1.8 / ANSSI R3")
    try:
        # Compter les updates dispo
        result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=10)
        updates = [l for l in result.stdout.splitlines() if "/" in l and "Listing" not in l]
        n = len(updates)
        security_n = sum(1 for line in updates if "security" in line.lower())

        if n > 5:
            severity = classify_update_severity(n, security_n)
            m.add(
                f"{n} mises a jour disponibles ({security_n} securite identifiees)",
                "Le nombre total ne prouve pas que toutes sont des failles critiques.",
                severity,
                verify="apt list --upgradable 2>/dev/null",
            )

        # Unattended-upgrades
        if not os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades"):
            m.add("unattended-upgrades absent", "Installer pour les mises a jour de securite auto.", "MEDIUM")
    except: pass
    m.finalize()
    return m


def scan_fs_link_protections(sysctl_root="/proc/sys/fs"):
    """Retourne les protections de fichiers temporaires absentes ou trop faibles."""
    checks = {
        "protected_hardlinks": (1, "Hardlinks non proteges"),
        "protected_symlinks": (1, "Symlinks non proteges"),
        "protected_fifos": (1, "FIFO non proteges"),
        "protected_regular": (1, "Fichiers reguliers non proteges"),
    }
    findings = []
    for name, (minimum, title) in checks.items():
        path = os.path.join(sysctl_root, name)
        try:
            with open(path, encoding="utf-8") as f:
                value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        if value < minimum:
            findings.append((title, path, value, minimum))
    return findings


def scan_unprivileged_bpf(path="/proc/sys/kernel/unprivileged_bpf_disabled"):
    """Retourne 0 si les appels BPF non privilegies sont autorises."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_unrestricted_io_uring(path="/proc/sys/kernel/io_uring_disabled"):
    """Retourne 0 lorsque tous les utilisateurs peuvent creer une instance io_uring."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def kernel_sysctl_is_unsafe(name, value, expected=None):
    """Compare un sysctl sans signaler comme faible un mode plus strict."""
    minimums = {
        "kernel.kptr_restrict": 1,
        "kernel.yama.ptrace_scope": 1,
        "kernel.perf_event_paranoid": 2,
    }
    if name in minimums:
        try:
            return int(value) < minimums[name]
        except ValueError:
            return True
    if expected is None:
        expected = {"kernel.dmesg_restrict": "1"}.get(name)
    return expected is not None and value != expected


def audit_kernel():
    m = Module("Kernel & Protections", 14, "CIS 1.6 / ANSSI R14")
    checks = {
        "/proc/sys/kernel/randomize_va_space": ("2", "ASLR desactive", "CRITICAL"),
        "/proc/sys/kernel/kptr_restrict": ("1", "kptr_restrict < 1", "MEDIUM"),
        "/proc/sys/kernel/dmesg_restrict": ("1", "dmesg accessible", "LOW"),
        "/proc/sys/kernel/yama/ptrace_scope": ("1", "ptrace non restreint", "MEDIUM"),
        "/proc/sys/kernel/perf_event_paranoid": ("2", "Perf expose le kernel aux utilisateurs non privilegies", "MEDIUM"),
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
            prefix = "/proc/sys/"
            name = path[len(prefix):].replace("/", ".") if path.startswith(prefix) else path
            if kernel_sysctl_is_unsafe(name, val, expected):
                comparator = "minimum" if name in (
                    "kernel.kptr_restrict", "kernel.yama.ptrace_scope",
                    "kernel.perf_event_paranoid",
                ) else "attendu"
                m.add(msg, f"{path} = {val} ({comparator}: {expected})", sev,
                      verify=f"cat {path}")
        except: pass

    # Ces sysctl bloquent plusieurs pieges inter-utilisateurs dans les
    # repertoires partages (notamment /tmp), meme si le sticky bit est present.
    for title, path, value, minimum in scan_fs_link_protections():
        m.add(
            title,
            f"{path} = {value} (minimum: {minimum}). Un autre utilisateur peut exploiter un fichier, lien ou FIFO piege dans un repertoire partage.",
            "MEDIUM",
            verify=f"cat {path}",
        )

    if scan_unprivileged_bpf() == 0:
        path = "/proc/sys/kernel/unprivileged_bpf_disabled"
        m.add(
            "BPF accessible aux utilisateurs non privilegies",
            f"{path} = 0. Le syscall bpf() reste disponible sans CAP_BPF ou CAP_SYS_ADMIN, ce qui elargit la surface d'attaque du kernel.",
            "MEDIUM",
            verify=f"cat {path}",
        )

    # La documentation du kernel indique explicitement que restreindre
    # io_uring reduit sa surface d'attaque. Les modes 1 (groupe dedie) et 2
    # (desactivation globale) sont acceptes pour les machines qui en ont besoin.
    if scan_unrestricted_io_uring() == 0:
        path = "/proc/sys/kernel/io_uring_disabled"
        m.add(
            "io_uring accessible a tous les utilisateurs",
            f"{path} = 0. Tout processus peut creer une instance io_uring ; utiliser 1 ou 2 reduit la surface d'attaque si les applications le permettent.",
            "LOW",
            verify=f"cat {path}",
        )

    # Kernel version
    try:
        uname = os.uname()
        major, minor = map(int, uname.release.split(".")[:2])
        if major < 5 or (major == 5 and minor < 10):
            m.add("Kernel obsolete", f"{uname.release} — passer a 5.10+ ou 6.x.", "HIGH")
    except: pass

    m.finalize()
    return m


def classify_deleted_executable(target):
    """Evalue le contexte sans confondre mise a jour et effacement suspect."""
    clean_path = target[:-10] if target.endswith(" (deleted)") else target
    suspicious_roots = ("/tmp/", "/var/tmp/", "/dev/shm/")
    return "HIGH" if clean_path.startswith(suspicious_roots) else "LOW"


def shadow_permissions_unsafe(mode, owner_uid, group_name):
    """Accepte notamment le standard 0640 root:shadow, refuse les acces larges."""
    mode = stat.S_IMODE(mode)
    if owner_uid != 0:
        return True
    if mode & 0o007:  # aucun droit pour les autres
        return True
    if mode & 0o030:  # groupe: ni ecriture ni execution
        return True
    if mode & 0o040 and group_name not in ("root", "shadow"):
        return True
    return False


def scan_deleted_executables(proc_root="/proc"):
    """Retourne les processus dont l'executable a ete supprime du disque."""
    found = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return found

    for pid in entries:
        if not pid.isdigit():
            continue
        proc_dir = os.path.join(proc_root, pid)
        try:
            target = os.readlink(os.path.join(proc_dir, "exe"))
            if not target.endswith(" (deleted)"):
                continue
            name = "unknown"
            try:
                with open(os.path.join(proc_dir, "comm"), encoding="utf-8", errors="replace") as f:
                    name = f.read().strip() or name
            except OSError:
                pass
            found.append({"pid": int(pid), "name": name, "target": target})
        except (OSError, ValueError):
            # Le processus peut disparaitre pendant le scan ou etre inaccessible.
            continue
    return sorted(found, key=lambda item: item["pid"])


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

        # Un programme peut continuer a tourner apres la suppression de son
        # binaire. Cela peut etre legitime apres une mise a jour, mais aussi
        # indiquer qu'un malware essaie d'effacer sa trace sur le disque.
        for proc in scan_deleted_executables():
            severity = classify_deleted_executable(proc["target"])
            if severity == "HIGH":
                title = "Binaire supprime dans un dossier temporaire"
                context = "Chemin inhabituel : examiner rapidement le processus."
            else:
                title = "Service a redemarrer apres mise a jour"
                context = "Frequent apres une mise a jour ; ce fait seul ne prouve pas un malware."
            m.add(
                title,
                f"PID {proc['pid']} ({proc['name']}) utilise encore {proc['target']}. {context}",
                severity,
                verify=f"sudo ls -l /proc/{proc['pid']}/exe; sudo ps -fp {proc['pid']}",
            )
    except: pass
    m.finalize()
    return m


def audit_filesystem():
    m = Module("Systeme de fichiers", 10, "CIS 1.1 / ANSSI R28")
    try:
        # /tmp executable (fallback mount si findmnt absent)
        tmp_opts = subprocess.run(["findmnt", "/tmp", "-o", "OPTIONS", "-n"],
                                 capture_output=True, text=True, timeout=3)
        if tmp_opts.returncode != 0:
            tmp_opts = subprocess.run(["mount"], capture_output=True, text=True, timeout=3)
            noexec = "noexec" in tmp_opts.stdout and "/tmp " in tmp_opts.stdout
        else:
            noexec = "noexec" in tmp_opts.stdout
        if not noexec:
            m.add("/tmp executable", "Monter /tmp avec noexec,nosuid si compatible avec les applications.", "MEDIUM",
                  verify="findmnt /tmp -o TARGET,OPTIONS")

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

        # /etc/shadow doit appartenir a root. 0640 root:shadow est standard.
        try:
            shadow_stat = os.stat("/etc/shadow")
            try:
                shadow_group = grp.getgrgid(shadow_stat.st_gid).gr_name
            except KeyError:
                shadow_group = str(shadow_stat.st_gid)
            if shadow_permissions_unsafe(shadow_stat.st_mode, shadow_stat.st_uid, shadow_group):
                mode = stat.S_IMODE(shadow_stat.st_mode)
                m.add(
                    "Permissions /etc/shadow dangereuses",
                    f"Mode={mode:04o}, proprietaire UID={shadow_stat.st_uid}, groupe={shadow_group}.",
                    "CRITICAL",
                    verify="sudo stat -c '%a %U %G %n' /etc/shadow",
                )
        except: pass

    except Exception as e:
        m.add("Erreur audit FS", str(e), "MEDIUM")

    m.finalize()
    return m


def audit_logs():
    m = Module("Logs & Monitoring", 8, "CIS 4.x")
    try:
        if not os.path.exists("/etc/audit/auditd.conf"):
            m.add("auditd absent", "Installer auditd pour tracer les evenements securite.", "MEDIUM",
                  verify="systemctl status auditd --no-pager")

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
    icon = {"INFO": "i", "LOW": "i", "MEDIUM": "⚠", "HIGH": "▲", "CRITICAL": "☠"}
    col = {"INFO": C['D'], "LOW": C['B'], "MEDIUM": C['Y'], "HIGH": C['R'], "CRITICAL": C['R']+C['BO']}
    ico = icon.get(f.severity, "!")
    cc = col.get(f.severity, C['W'])
    print(f"  {cc}{ico} [{f.severity:8s}] {f.title}{C['E']}")
    print(f"     {C['D']}{f.detail}{C['E']}")
    if f.verify:
        print(f"     {C['B']}Verifier : {f.verify}{C['E']}")

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
        findings = len(m.findings)
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
            if f.verify:
                lines.append(f"         Verifier : {f.verify}")
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
    parser.add_argument("--allow-port", action="append", default=[], metavar="PORT",
                        help="Port wildcard attendu : reste visible en INFO sans penalite (repetable)")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.quiet:
        print(f"{C['Y']}[!] Lance avec sudo pour un audit complet.{C['E']}")

    modules = [
        audit_users(),
        audit_ssh(),
        audit_network(set(args.allow_port)),
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
                         "findings": [{"title": f.title, "severity": f.severity,
                                       "detail": f.detail, "verify": f.verify}
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
