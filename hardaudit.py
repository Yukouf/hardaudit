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


def scan_unprotected_reverse_paths(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces sans validation effective de l'adresse source IPv4."""
    try:
        with open(os.path.join(root, "all", "rp_filter"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        # Le loopback ne reçoit pas de trafic depuis le réseau. "all" et
        # "default" sont des modèles de configuration, pas des interfaces.
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "rp_filter"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # Le kernel applique le maximum entre conf/all et conf/interface.
        if max(all_value, interface_value) == 0:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unsafe_ipv4_source_routing(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui acceptent effectivement les routes source IPv4."""
    try:
        with open(os.path.join(root, "all", "accept_source_route"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(
                os.path.join(root, interface, "accept_source_route"), encoding="utf-8"
            ) as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # La documentation du kernel exige que la politique globale ET celle de
        # l'interface autorisent l'option SRR avant qu'un paquet soit accepté.
        if all_value == 1 and interface_value == 1:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unlogged_martian_interfaces(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui ne journalisent pas les paquets aux sources impossibles."""
    try:
        with open(os.path.join(root, "all", "log_martians"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "log_martians"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # Le kernel active ce journal si "all" OU la valeur locale vaut 1.
        if all_value == 0 and interface_value == 0:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_routed_loopback_interfaces(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces où 127/8 peut être routé hors du loopback."""
    try:
        with open(os.path.join(root, "all", "route_localnet"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "route_localnet"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # Le kernel utilise IN_DEV_ORCONF : la valeur "all" OU celle de
        # l'interface suffit à autoriser le routage des adresses 127/8.
        if all_value == 1 or interface_value == 1:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unsafe_ipv4_redirects(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui acceptent effectivement les redirects ICMP IPv4."""
    try:
        with open(os.path.join(root, "all", "accept_redirects"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "accept_redirects"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
            with open(os.path.join(root, interface, "forwarding"), encoding="utf-8") as f:
                forwarding = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # D'après la documentation réseau du kernel, un routeur exige que
        # "all" ET l'interface acceptent les redirects. Un hôte les accepte
        # dès que "all" OU l'interface les autorise.
        enabled = (
            all_value == 1 and interface_value == 1
            if forwarding == 1
            else all_value == 1 or interface_value == 1
        )
        if enabled:
            findings.append((interface, all_value, interface_value, forwarding))
    return findings


def scan_unsafe_ipv4_redirect_senders(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces routeur qui envoient effectivement des redirects ICMP."""
    try:
        with open(os.path.join(root, "all", "send_redirects"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "send_redirects"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
            with open(os.path.join(root, interface, "forwarding"), encoding="utf-8") as f:
                forwarding = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # Le kernel active send_redirects si "all" OU l'interface vaut 1,
        # mais un hote qui ne route pas n'emet pas ces messages.
        if forwarding == 1 and (all_value == 1 or interface_value == 1):
            findings.append((interface, all_value, interface_value, forwarding))
    return findings


def scan_unsafe_ipv6_redirects(root="/proc/sys/net/ipv6/conf"):
    """Liste les interfaces hote qui acceptent les redirects ICMPv6."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        # "all" et "default" sont des politiques, pas des interfaces. Le
        # loopback ne reçoit pas de redirects depuis un voisin réseau.
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "accept_redirects"), encoding="utf-8") as f:
                accept_redirects = int(f.read().strip())
            with open(os.path.join(root, interface, "forwarding"), encoding="utf-8") as f:
                forwarding = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # La valeur fonctionnelle documentée est active sur les interfaces
        # hôte et inactive sur les interfaces routeur.
        if accept_redirects == 1 and forwarding == 0:
            findings.append((interface, accept_redirects, forwarding))
    return findings


def scan_ipv6_routers_accepting_ra(root="/proc/sys/net/ipv6/conf"):
    """Liste les interfaces routeur qui acceptent encore les annonces IPv6."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "accept_ra"), encoding="utf-8") as f:
                accept_ra = int(f.read().strip())
            with open(os.path.join(root, interface, "forwarding"), encoding="utf-8") as f:
                forwarding = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # Le mode 2 outrepasse explicitement le comportement routeur : les RA
        # restent acceptées même quand le forwarding local est actif.
        if accept_ra == 2 and forwarding == 1:
            findings.append((interface, accept_ra, forwarding))
    return findings


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

        reverse_path_findings = scan_unprotected_reverse_paths()
        if reverse_path_findings:
            interfaces = ", ".join(item[0] for item in reverse_path_findings)
            m.add(
                "Validation anti-spoofing IPv4 desactivee",
                f"rp_filter vaut effectivement 0 sur : {interfaces}. Le mode 1 est strict ; utiliser 2 si le routage asymetrique exige un mode plus compatible.",
                "LOW",
                verify="sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; grep -H . /proc/sys/net/ipv4/conf/*/rp_filter",
            )

        source_routing = scan_unsafe_ipv4_source_routing()
        if source_routing:
            interfaces = ", ".join(item[0] for item in source_routing)
            m.add(
                "Routage impose par la source IPv4 accepte",
                f"accept_source_route vaut 1 globalement et sur : {interfaces}. Un paquet peut alors proposer lui-meme une partie de son trajet via l'option SRR ; desactiver sauf besoin de routage historique explicitement documente.",
                "HIGH",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/accept_source_route 2>/dev/null",
            )

        unlogged_martians = scan_unlogged_martian_interfaces()
        if unlogged_martians:
            interfaces = ", ".join(item[0] for item in unlogged_martians)
            m.add(
                "Paquets IPv4 aux sources impossibles non journalises",
                f"log_martians vaut effectivement 0 sur : {interfaces}. Le kernel rejettera encore selon ses controles reseau, mais l'indice disparait des logs ; activer apres avoir dimensionne la journalisation.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/log_martians 2>/dev/null; journalctl -k | grep -i martian",
            )

        routed_loopback = scan_routed_loopback_interfaces()
        if routed_loopback:
            interfaces = ", ".join(item[0] for item in routed_loopback)
            m.add(
                "Adresses loopback routables hors de l'hote",
                f"route_localnet autorise effectivement 127/8 sur : {interfaces}. Ce mode sert aux proxies transparents et a certaines redirections NAT, mais retire la protection qui traite normalement ces adresses comme impossibles sur le reseau.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/route_localnet 2>/dev/null; sudo nft list ruleset; sudo iptables-save",
            )

        redirect_findings = scan_unsafe_ipv4_redirects()
        if redirect_findings:
            interfaces = ", ".join(item[0] for item in redirect_findings)
            m.add(
                "Acceptation effective des redirects ICMP IPv4",
                f"Interfaces concernees : {interfaces}. Sur un hote, une valeur locale a 1 suffit meme si conf/all vaut 0 ; un voisin reseau peut alors tenter de modifier la route utilisee. Desactiver apres verification des besoins de routage.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*/}{accept_redirects,forwarding} 2>/dev/null",
            )

        redirect_senders = scan_unsafe_ipv4_redirect_senders()
        if redirect_senders:
            interfaces = ", ".join(item[0] for item in redirect_senders)
            m.add(
                "Emission effective de redirects ICMP IPv4",
                f"Interfaces routeur concernees : {interfaces}. Une valeur locale a 1 suffit meme si conf/all vaut 0 ; ces messages peuvent faire choisir une autre passerelle aux machines voisines. Desactiver sauf besoin de routage explicite.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*/}{send_redirects,forwarding} 2>/dev/null",
            )

        ipv6_redirects = scan_unsafe_ipv6_redirects()
        if ipv6_redirects:
            interfaces = ", ".join(item[0] for item in ipv6_redirects)
            m.add(
                "Acceptation effective des redirects ICMPv6",
                f"Interfaces hote concernees : {interfaces}. Un voisin IPv6 peut proposer une autre route ; desactiver accept_redirects sauf besoin explicite et verifier aussi les interfaces virtuelles.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}{accept_redirects,forwarding} 2>/dev/null",
            )

        ipv6_routers_accepting_ra = scan_ipv6_routers_accepting_ra()
        if ipv6_routers_accepting_ra:
            interfaces = ", ".join(item[0] for item in ipv6_routers_accepting_ra)
            m.add(
                "Routeur acceptant les Router Advertisements IPv6",
                f"Interfaces concernees : {interfaces}. accept_ra=2 outrepasse le mode routeur : un voisin peut encore fournir une route ou des prefixes IPv6. Garder ce mode seulement pour un routeur qui doit aussi apprendre sa connectivite par RA.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}{accept_ra,forwarding} 2>/dev/null",
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


def scan_unlimited_user_pipe_memory(
    soft_path="/proc/sys/fs/pipe-user-pages-soft",
    hard_path="/proc/sys/fs/pipe-user-pages-hard",
):
    """Retourne les quotas quand aucune borne mémoire par utilisateur n'est active."""
    try:
        with open(soft_path, encoding="utf-8") as f:
            soft_limit = int(f.read().strip())
        with open(hard_path, encoding="utf-8") as f:
            hard_limit = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # Le kernel documente 0 comme « aucune limite » pour les deux réglages.
    # Une borne souple positive limite déjà la taille des nouveaux pipes après
    # dépassement, même si la borne dure reste à sa valeur par défaut 0.
    if soft_limit == 0 and hard_limit == 0:
        return soft_limit, hard_limit
    return None


def scan_proc_hidepid(mountinfo_path="/proc/self/mountinfo"):
    """Retourne le mode hidepid du procfs monte sur /proc (0 par defaut)."""
    aliases = {"noaccess": 1, "invisible": 2, "ptraceable": 4}
    try:
        with open(mountinfo_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None

    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if (len(fields) <= separator + 3 or fields[4] != "/proc"
                or fields[separator + 1] != "proc"):
            continue
        options = fields[5].split(",") + fields[separator + 3].split(",")
        raw_mode = next((option.split("=", 1)[1] for option in options
                         if option.startswith("hidepid=")), "0")
        try:
            return int(raw_mode)
        except ValueError:
            return aliases.get(raw_mode)
    return None


def scan_mount_options(target, mountinfo_path="/proc/self/mountinfo"):
    """Retourne les options effectives du montage exact vise, si present."""
    try:
        with open(mountinfo_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None

    # mountinfo encode notamment les espaces sous la forme \040.
    escaped_target = target.replace("\\", "\\134").replace(" ", "\\040")
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 3 or fields[4] != escaped_target:
            continue
        return set(fields[5].split(",")) | set(fields[separator + 3].split(","))
    return None


def scan_unsafe_suid_dumps(
    suid_dumpable_path="/proc/sys/fs/suid_dumpable",
    core_pattern_path="/proc/sys/kernel/core_pattern",
):
    """Retourne les reglages dangereux de core dump des processus privilegies."""
    try:
        with open(suid_dumpable_path, encoding="utf-8") as f:
            mode = int(f.read().strip())
        with open(core_pattern_path, encoding="utf-8") as f:
            pattern = f.read().strip()
    except (OSError, ValueError):
        return None

    # Mode 1 retire les protections. Le mode 2 n'est sur, d'apres la
    # documentation du kernel, qu'avec un handler pipe ou un chemin absolu.
    if mode == 1 or (mode == 2 and not pattern.startswith(("|", "/"))):
        return mode, pattern
    return None


def scan_unbounded_core_pipe(
    core_pattern_path="/proc/sys/kernel/core_pattern",
    core_pipe_limit_path="/proc/sys/kernel/core_pipe_limit",
):
    """Retourne un handler de core dump pipe sans limite de concurrence."""
    try:
        with open(core_pattern_path, encoding="utf-8") as f:
            pattern = f.read().strip()
        with open(core_pipe_limit_path, encoding="utf-8") as f:
            limit = int(f.read().strip())
    except (OSError, ValueError):
        return None
    if pattern.startswith("|") and limit == 0:
        return pattern, limit
    return None


def scan_unprivileged_bpf(path="/proc/sys/kernel/unprivileged_bpf_disabled"):
    """Retourne 0 si les appels BPF non privilegies sont autorises."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_bpf_jit_hardening(path="/proc/sys/net/core/bpf_jit_harden"):
    """Retourne le mode si le JIT BPF n'est pas durci pour tous les utilisateurs."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value in (0, 1) else None


def scan_unrestricted_io_uring(path="/proc/sys/kernel/io_uring_disabled"):
    """Retourne 0 lorsque tous les utilisateurs peuvent creer une instance io_uring."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_unmediated_unprivileged_io_uring(
    io_uring_path="/proc/sys/kernel/io_uring_disabled",
    apparmor_path="/proc/sys/kernel/apparmor_restrict_unprivileged_io_uring",
):
    """Détecte io_uring ouvert sans la médiation AppArmor optionnelle d'Ubuntu."""
    try:
        with open(io_uring_path, encoding="utf-8") as f:
            io_uring_policy = int(f.read().strip())
        with open(apparmor_path, encoding="utf-8") as f:
            apparmor_policy = int(f.read().strip())
    except (OSError, ValueError):
        # Cette interface AppArmor n'existe que sur les kernels compatibles.
        return None
    if io_uring_policy == 0 and apparmor_policy == 0:
        return io_uring_policy, apparmor_policy
    return None


def scan_unprivileged_tty_ldisc_autoload(path="/proc/sys/dev/tty/ldisc_autoload"):
    """Retourne 1 si un utilisateur sans CAP_SYS_MODULE peut demander un ldisc."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 1 else None


def scan_legacy_tiocsti_enabled(path="/proc/sys/dev/tty/legacy_tiocsti"):
    """Retourne 1 si l'injection TIOCSTI historique reste permise sans CAP_SYS_ADMIN."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 1 else None


def scan_kexec_enabled(path="/proc/sys/kernel/kexec_load_disabled"):
    """Retourne 0 si le chargement d'un nouveau kernel par kexec reste autorise."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_module_loading_unlocked(path="/proc/sys/kernel/modules_disabled"):
    """Retourne 0 si le chargement et le retrait de modules restent autorises."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_unprivileged_userfaultfd(path="/proc/sys/vm/unprivileged_userfaultfd"):
    """Retourne 1 si userfaultfd peut intercepter des fautes kernel sans privilege."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 1 else None


def scan_delegated_userfaultfd(path="/dev/userfaultfd"):
    """Retourne les droits qui deleguent userfaultfd a un compte non-root.

    Le peripherique contourne volontairement vm.unprivileged_userfaultfd : ses
    permissions constituent donc une politique d'acces independante.
    """
    try:
        info = os.stat(path)
    except OSError:
        return None
    mode = info.st_mode & 0o777
    if info.st_uid != 0 or mode & 0o066:
        return mode, info.st_uid, info.st_gid
    return None


def scan_executable_memfd_default(path="/proc/sys/vm/memfd_noexec"):
    """Retourne 0 lorsque memfd_create() produit un fichier executable par defaut."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_unrestricted_unprivileged_userns(
    userns_path="/proc/sys/kernel/unprivileged_userns_clone",
    apparmor_path="/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
):
    """Détecte le cas Ubuntu/AppArmor où userns est actif sans confinement dédié."""
    try:
        with open(userns_path, encoding="utf-8") as f:
            userns_enabled = int(f.read().strip())
        with open(apparmor_path, encoding="utf-8") as f:
            apparmor_restricted = int(f.read().strip())
    except (OSError, ValueError):
        # Ce contrôle est spécifique aux kernels qui exposent les deux sysctl.
        return None
    if userns_enabled == 1 and apparmor_restricted == 0:
        return userns_enabled, apparmor_restricted
    return None


def scan_unconfined_userns_exception(
    userns_path="/proc/sys/kernel/unprivileged_userns_clone",
    restriction_path="/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    unconfined_path="/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined",
):
    """Détecte une médiation userns AppArmor sans restriction des profils unconfined."""
    try:
        values = []
        for path in (userns_path, restriction_path, unconfined_path):
            with open(path, encoding="utf-8") as f:
                values.append(int(f.read().strip()))
    except (OSError, ValueError):
        # Ces interfaces sont spécifiques aux kernels AppArmor compatibles.
        return None
    userns_enabled, apparmor_restricted, unconfined_restricted = values
    if userns_enabled == 1 and apparmor_restricted == 1 and unconfined_restricted == 0:
        return tuple(values)
    return None


def scan_zero_page_mappable(path="/proc/sys/vm/mmap_min_addr"):
    """Retourne 0 si les processus peuvent demander une projection a l'adresse nulle."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_kernel_lockdown_disabled(path="/sys/kernel/security/lockdown"):
    """Retourne le mode courant si l'interface Lockdown existe et vaut none."""
    try:
        with open(path, encoding="utf-8") as f:
            modes = f.read().strip().split()
    except OSError:
        return None
    selected = next((mode[1:-1] for mode in modes
                     if mode.startswith("[") and mode.endswith("]")), None)
    return selected if selected == "none" else None


def scan_active_lsms(path="/sys/kernel/security/lsm"):
    """Retourne les modules de securite actifs, sans deduire l'etat de leurs politiques."""
    try:
        with open(path, encoding="utf-8") as f:
            names = [name.strip() for name in f.read().split(",") if name.strip()]
    except OSError:
        return None
    return names


def scan_binfmt_credential_entries(root="/proc/sys/fs/binfmt_misc"):
    """Liste les formats actifs dont l'interpreteur herite des droits du binaire."""
    try:
        names = os.listdir(root)
    except OSError:
        return []

    risky = []
    for name in sorted(names):
        if name in ("register", "status"):
            continue
        path = os.path.join(root, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        if not lines or lines[0].strip() != "enabled":
            continue
        flags = next(
            (line.split(":", 1)[1].strip() for line in lines
             if line.startswith("flags:")),
            "",
        )
        interpreter = next(
            (line.split(None, 1)[1].strip() for line in lines
             if line.startswith("interpreter ")),
            "inconnu",
        )
        if "C" in flags:
            risky.append((name, interpreter, flags))
    return risky


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


def scan_unlimited_kernel_oopses(
    panic_path="/proc/sys/kernel/panic_on_oops",
    limit_path="/proc/sys/kernel/oops_limit",
):
    """Retourne la politique si aucun oops ne peut provoquer de panic.

    Un oops peut laisser le kernel en vie apres avoir saute des nettoyages. Le
    risque vise ici est le cas explicite et incontestable documente par le
    kernel : panic_on_oops=0 combine a oops_limit=0 (compteur desactive).
    """
    try:
        with open(panic_path, encoding="utf-8") as f:
            panic_on_oops = int(f.read().strip())
        with open(limit_path, encoding="utf-8") as f:
            oops_limit = int(f.read().strip())
    except (OSError, ValueError):
        return None
    if panic_on_oops == 0 and oops_limit == 0:
        return panic_on_oops, oops_limit
    return None


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

    unsafe_suid_dumps = scan_unsafe_suid_dumps()
    if unsafe_suid_dumps is not None:
        mode, pattern = unsafe_suid_dumps
        reason = (
            "le mode debug retire les protections des processus privilegies"
            if mode == 1 else
            "le mode suidsafe exige un handler pipe ou un chemin absolu"
        )
        m.add(
            "Core dumps SUID actifs sans destination sure",
            f"fs.suid_dumpable = {mode}, kernel.core_pattern = {pattern!r} : {reason}.",
            "MEDIUM",
            verify="sysctl fs.suid_dumpable kernel.core_pattern",
        )

    # Un core_pattern pipe contourne RLIMIT_CORE. Avec core_pipe_limit=0, le
    # kernel accepte un nombre illimite de collecteurs simultanes ; une tempete
    # de crash peut donc amplifier la consommation CPU, memoire et processus.
    unbounded_core_pipe = scan_unbounded_core_pipe()
    if unbounded_core_pipe is not None:
        pattern, limit = unbounded_core_pipe
        m.add(
            "Collecteurs de core dump simultanes sans limite",
            f"kernel.core_pattern = {pattern!r} et kernel.core_pipe_limit = {limit}. Les core dumps pipes ignorent RLIMIT_CORE et peuvent lancer un nombre illimite de collecteurs ; fixer une borne positive adaptee a la charge.",
            "LOW",
            verify="sysctl kernel.core_pattern kernel.core_pipe_limit; ulimit -c",
        )

    # Continuer apres un oops peut laisser des ressources ou verrous dans un
    # etat incoherent. Le kernel borne par defaut ces repetitions ; oops_limit=0
    # desactive exactement cette borne. Ne pas imposer panic_on_oops=1, qui peut
    # transformer un bug recuperable en indisponibilite immediate.
    if scan_unlimited_kernel_oopses() == (0, 0):
        m.add(
            "Oops kernel repetables sans limite",
            "kernel.panic_on_oops = 0 et kernel.oops_limit = 0. Le kernel tente de continuer et ne panique jamais selon le nombre d'oops ; conserver une borne positive pour limiter les exploitations qui repetent une faute kernel.",
            "LOW",
            verify="sysctl kernel.panic_on_oops kernel.oops_limit",
        )

    # Sans aucun quota par UID, un compte ordinaire peut accumuler la mémoire
    # noyau des pipes. La borne souple suffit déjà à réduire les nouveaux pipes ;
    # ne pas exiger une borne dure lorsque la valeur par défaut 0 est compensée.
    if scan_unlimited_user_pipe_memory() == (0, 0):
        m.add(
            "Aucune limite de memoire des pipes par utilisateur",
            "fs.pipe-user-pages-soft = 0 et fs.pipe-user-pages-hard = 0 : aucune limite par utilisateur n'est appliquee. Fixer au moins une borne souple positive adaptee a la charge pour reduire un epuisement de memoire noyau par un compte local.",
            "LOW",
            verify="sysctl fs.pipe-user-pages-soft fs.pipe-user-pages-hard; getconf PAGE_SIZE",
        )

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

    # Le kernel documente que ce durcissement limite le JIT spraying. Le mode 1
    # ne couvre que les processus sans CAP_BPF/CAP_SYS_ADMIN ; le mode 2 couvre
    # aussi les chargeurs privilegies, au prix possible de performances.
    jit_hardening = scan_bpf_jit_hardening()
    if jit_hardening in (0, 1):
        path = "/proc/sys/net/core/bpf_jit_harden"
        scope = "desactive" if jit_hardening == 0 else "limite aux utilisateurs non privilegies"
        m.add(
            "Durcissement du JIT BPF incomplet",
            f"{path} = {jit_hardening} ({scope}). Le mode 2 durcit tous les programmes BPF JIT et reduit le risque de JIT spraying, avec un possible cout de performance.",
            "LOW",
            verify=f"cat {path}; cat /proc/sys/kernel/unprivileged_bpf_disabled",
        )

    # La documentation du kernel indique explicitement que restreindre
    # io_uring reduit sa surface d'attaque. Les modes 1 (groupe dedie) et 2
    # (desactivation globale) sont acceptes pour les machines qui en ont besoin.
    if scan_unrestricted_io_uring() == 0:
        path = "/proc/sys/kernel/io_uring_disabled"
        unmediated = scan_unmediated_unprivileged_io_uring() == (0, 0)
        detail = (
            f"{path} = 0 et kernel.apparmor_restrict_unprivileged_io_uring = 0. "
            "Tout processus peut creer une instance io_uring sans la mediation AppArmor "
            "optionnelle de ce kernel ; activer cette mediation, ou utiliser le mode global "
            "1/2 apres test de compatibilite."
            if unmediated else
            f"{path} = 0. Tout processus peut creer une instance io_uring ; utiliser 1 ou 2 "
            "reduit la surface d'attaque si les applications le permettent."
        )
        m.add(
            "io_uring accessible a tous les utilisateurs",
            detail,
            "LOW",
            verify=(
                f"cat {path}; [ ! -e /proc/sys/kernel/apparmor_restrict_unprivileged_io_uring ] "
                "|| cat /proc/sys/kernel/apparmor_restrict_unprivileged_io_uring"
            ),
        )

    # Avec 0, les comptes sans CAP_SYS_PTRACE restent limites aux fautes en
    # espace utilisateur. La documentation upstream indique explicitement que
    # cette restriction peut rendre certaines vulnerabilites plus difficiles
    # a exploiter. /dev/userfaultfd doit etre audite separement s'il existe.
    if scan_unprivileged_userfaultfd() == 1:
        path = "/proc/sys/vm/unprivileged_userfaultfd"
        m.add(
            "userfaultfd non restreint pour les utilisateurs",
            f"{path} = 1. Un compte sans CAP_SYS_PTRACE peut aussi intercepter des fautes venant du kernel ; utiliser 0 sauf besoin documente. Verifier aussi les droits de /dev/userfaultfd s'il existe.",
            "LOW",
            verify=f"cat {path}; [ ! -e /dev/userfaultfd ] || stat -c '%A %U %G %n' /dev/userfaultfd",
        )

    # /dev/userfaultfd est une seconde porte, independante du sysctl : le
    # kernel autorise toujours ses utilisateurs a intercepter les fautes venant
    # du kernel. Signaler toute delegation, même si le sysctl protecteur vaut 0.
    delegated_userfaultfd = scan_delegated_userfaultfd()
    if delegated_userfaultfd is not None:
        mode, uid, gid = delegated_userfaultfd
        m.add(
            "Acces userfaultfd delegue hors de root",
            f"/dev/userfaultfd a les droits {mode:03o} et appartient a UID {uid}, GID {gid}. Les comptes autorises par ce peripherique peuvent intercepter les fautes venant du kernel meme si vm.unprivileged_userfaultfd = 0 ; conserver uniquement une delegation explicitement requise.",
            "LOW",
            verify="sysctl vm.unprivileged_userfaultfd; stat -c '%a %A %U %G %n' /dev/userfaultfd; command -v getfacl >/dev/null && getfacl -cp /dev/userfaultfd",
        )

    # Depuis Linux 6.3, ce réglage permet de ne plus rendre implicitement
    # exécutables les fichiers anonymes créés par memfd_create(). Le mode 1
    # exige une demande explicite ; le mode 2 refuse même cette demande.
    if scan_executable_memfd_default() == 0:
        path = "/proc/sys/vm/memfd_noexec"
        m.add(
            "Fichiers memfd executables par defaut",
            f"{path} = 0. memfd_create() implique encore MFD_EXEC, ce qui facilite l'execution de code sans fichier persistant ; utiliser 1, ou 2 si aucun runtime ne requiert de memfd executable.",
            "LOW",
            verify=f"cat {path}",
        )

    # Certains kernels Ubuntu laissent userns disponible pour les applications
    # tout en demandant à AppArmor de l'autoriser profil par profil. Ne signaler
    # que les machines qui exposent explicitement ce mécanisme mais le désactivent.
    if scan_unrestricted_unprivileged_userns() == (1, 0):
        userns_path = "/proc/sys/kernel/unprivileged_userns_clone"
        apparmor_path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
        m.add(
            "Namespaces utilisateur non confines par AppArmor",
            f"{userns_path} = 1 et {apparmor_path} = 0. Les comptes ordinaires peuvent creer un user namespace sans la mediation AppArmor prevue par ce kernel ; activer la restriction seulement apres avoir profile les navigateurs et conteneurs qui en dependent.",
            "LOW",
            verify=f"cat {userns_path} {apparmor_path}; runuser -u nobody -- unshare --user --map-root-user true",
        )

    # Ubuntu recommande aussi de restreindre les profils explicitement marques
    # unconfined. Sans ce second verrou, leur politique peut encore autoriser la
    # creation de userns meme si la mediation generale est active.
    if scan_unconfined_userns_exception() == (1, 1, 0):
        path = "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined"
        m.add(
            "Exception userns des profils AppArmor unconfined active",
            f"{path} = 0 alors que la mediation userns AppArmor est active. Les profils marques unconfined peuvent conserver leur propre permission de creer un namespace utilisateur ; utiliser 1 apres verification des profils applicatifs.",
            "LOW",
            verify="sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.apparmor_restrict_unprivileged_unconfined",
        )

    # Interdire la premiere page empeche un processus non privilegie d'y placer
    # des donnees qu'un bug de dereferencement NULL du kernel pourrait utiliser.
    # Toute valeur positive active le garde-fou ; 64 KiB est le choix courant.
    if scan_zero_page_mappable() == 0:
        path = "/proc/sys/vm/mmap_min_addr"
        m.add(
            "Page memoire nulle accessible aux processus",
            f"{path} = 0. Aucun plancher n'empeche mmap() de projeter des donnees pres de l'adresse nulle ; utiliser une valeur positive (souvent 65536) sauf besoin logiciel historique.",
            "MEDIUM",
            verify=f"cat {path}",
        )

    # Le kernel peut charger a la demande une discipline de ligne TTY. Avec
    # cette valeur a 0, seuls les processus ayant CAP_SYS_MODULE peuvent
    # declencher cet autoload, ce qui reduit la surface exposee aux comptes locaux.
    if scan_unprivileged_tty_ldisc_autoload() == 1:
        path = "/proc/sys/dev/tty/ldisc_autoload"
        m.add(
            "Autoload TTY accessible aux utilisateurs non privilegies",
            f"{path} = 1. Un compte local peut demander le chargement automatique d'une discipline TTY absente ; utiliser 0 si cette compatibilite n'est pas requise.",
            "LOW",
            verify=f"cat {path}",
        )

    # TIOCSTI peut pousser des caracteres dans un terminal de controle. Le
    # kernel qualifie cette interface historique de mecanisme d'escalade
    # dangereux ; la valeur 0 la reserve aux processus ayant CAP_SYS_ADMIN.
    if scan_legacy_tiocsti_enabled() == 1:
        path = "/proc/sys/dev/tty/legacy_tiocsti"
        m.add(
            "Injection terminal TIOCSTI historique autorisee",
            f"{path} = 1. Un processus partageant un terminal peut y injecter des frappes ; utiliser 0 sauf dependance ancienne confirmee (les processus CAP_SYS_ADMIN restent autorises).",
            "LOW",
            verify=f"cat {path}",
        )

    # Ce verrou est irreversible jusqu'au prochain demarrage. Il empeche meme
    # root de remplacer le kernel en memoire, mais doit rester disponible sur
    # les hotes qui utilisent volontairement kexec ou kdump.
    if scan_kexec_enabled() == 0:
        path = "/proc/sys/kernel/kexec_load_disabled"
        m.add(
            "Remplacement du kernel par kexec encore autorise",
            f"{path} = 0. Le verrou kexec n'est pas active ; envisager 1 seulement si ni kexec ni kdump ne sont requis (irreversible jusqu'au redemarrage).",
            "LOW",
            verify=f"cat {path}",
        )

    # Sur une appliance stable, ce verrou retire toute la surface de chargement
    # dynamique. Il bloque aussi le retrait des modules et ne peut pas etre leve
    # avant un redemarrage : a eviter si hotplug, DKMS ou pilotes tardifs sont requis.
    if scan_module_loading_unlocked() == 0:
        path = "/proc/sys/kernel/modules_disabled"
        m.add(
            "Chargement des modules noyau encore autorise",
            f"{path} = 0. Une appliance stable peut utiliser 1 apres avoir charge tous ses pilotes ; ce verrou bloque chargement et retrait et est irreversible jusqu'au redemarrage.",
            "LOW",
            verify=f"cat {path}; lsmod",
        )

    # Lockdown limite ce que même root peut demander au kernel. Ne signaler que
    # si le kernel expose l'interface : son absence ne prouve pas un mode faible.
    if scan_kernel_lockdown_disabled() == "none":
        path = "/sys/kernel/security/lockdown"
        m.add(
            "Kernel Lockdown disponible mais inactif",
            f"{path} selectionne [none]. Les modes integrity/confidentiality bloquent des interfaces permettant de modifier ou d'extraire des donnees du kernel ; a reserver aux hotes dont les modules, kexec et outils de diagnostic ont ete testes.",
            "LOW",
            verify=f"cat {path}; cat /proc/cmdline",
        )

    # Plusieurs LSM peuvent coexister : la liste effective est donc plus fiable
    # qu'un simple paquet installe. capability, Yama, Lockdown et Landlock sont
    # utiles, mais ne remplacent pas une politique MAC systeme.
    active_lsms = scan_active_lsms()
    mac_lsms = {"apparmor", "selinux", "smack", "tomoyo"}
    if active_lsms is not None and not mac_lsms.intersection(active_lsms):
        path = "/sys/kernel/security/lsm"
        m.add(
            "Aucun LSM de controle d'acces obligatoire actif",
            f"{path} contient {','.join(active_lsms) or 'une liste vide'}. Les protections presentes ne fournissent pas de politique MAC systeme ; activer et configurer AppArmor, SELinux, Smack ou TOMOYO selon la distribution.",
            "MEDIUM",
            verify=f"cat {path}; cat /proc/cmdline",
        )

    # Le drapeau C de binfmt_misc calcule les credentials d'apres le binaire
    # lance, pas l'interpreteur. La documentation du kernel avertit donc qu'un
    # binaire setuid root fait lui aussi tourner l'interpreteur en root.
    credential_entries = scan_binfmt_credential_entries()
    if credential_entries:
        entries = ", ".join(
            f"{name} -> {interpreter} (flags={flags})"
            for name, interpreter, flags in credential_entries
        )
        m.add(
            "Interpreteurs binfmt_misc autorises a heriter de privileges",
            f"Entrees actives avec le drapeau C : {entries}. Un binaire setuid root correspondant execute l'interpreteur avec les droits root ; conserver ce drapeau uniquement pour un interpreteur strictement maitrise.",
            "HIGH",
            verify="grep -H -E '^(enabled|interpreter |flags:)' /proc/sys/fs/binfmt_misc/* 2>/dev/null",
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

        # /dev/shm est un tmpfs 1777 destine a la memoire partagee POSIX. Sans
        # noexec, tout compte local peut aussi y deposer et lancer un binaire
        # directement depuis la RAM. nodev et nosuid completent ce cloisonnement.
        shm_options = scan_mount_options("/dev/shm")
        if shm_options is not None:
            missing = {"nodev", "nosuid", "noexec"} - shm_options
            if missing:
                missing_text = ",".join(sorted(missing))
                m.add(
                    "/dev/shm insuffisamment cloisonne",
                    f"Options absentes : {missing_text}. Ajouter nodev,nosuid,noexec si les applications le permettent ; noexec bloque l'execution directe mais pas la lecture par un interpreteur.",
                    "LOW",
                    verify="findmnt -T /dev/shm -o TARGET,FSTYPE,OPTIONS",
                )

        # Sans hidepid, un compte local peut lire les metadonnees de processus
        # d'autres utilisateurs. C'est surtout pertinent sur les hotes partages.
        if scan_proc_hidepid() == 0:
            m.add(
                "Metadonnees des processus visibles entre utilisateurs",
                "/proc utilise le mode hidepid=0 par defaut. Sur un hote multi-utilisateur, hidepid=1 ou 2 limite l'inventaire des commandes et services des autres comptes ; verifier la compatibilite des outils de supervision.",
                "LOW",
                verify="findmnt /proc -o TARGET,FSTYPE,OPTIONS; runuser -u nobody -- test -r /proc/1/status",
            )

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
