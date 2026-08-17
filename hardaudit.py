#!/usr/bin/env python3
"""
HardAudit — Outil d'audit de securite pour VMs Linux.
Score sur 100, 9 modules, couleurs ANSI, export rapport.
Usage : sudo python3 hardaudit.py [--json | --quiet]
"""

import os, sys, re, pwd, grp, stat, socket, subprocess, json, time
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


def scan_ipv4_ipsec_bypass_interfaces(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui désactivent la politique ou les transformations IPsec."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        # Le loopback utilise couramment ces exceptions et ne reçoit pas de
        # trafic d'un voisin. all/default sont des modèles, pas des interfaces.
        if interface in ("all", "default", "lo"):
            continue
        try:
            values = []
            for name in ("disable_policy", "disable_xfrm"):
                with open(os.path.join(root, interface, name), encoding="utf-8") as f:
                    values.append(int(f.read().strip()))
        except (OSError, ValueError):
            continue
        disable_policy, disable_xfrm = values
        if disable_policy == 1 or disable_xfrm == 1:
            findings.append((interface, disable_policy, disable_xfrm))
    return findings


def scan_gratuitous_arp_updates(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui acceptent encore les annonces ARP gratuites."""
    try:
        with open(
            os.path.join(root, "all", "drop_gratuitous_arp"), encoding="utf-8"
        ) as f:
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
                os.path.join(root, interface, "drop_gratuitous_arp"),
                encoding="utf-8",
            ) as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # arp.c utilise IN_DEV_ORCONF : la valeur globale OU locale suffit
        # à jeter une trame ARP gratuite avant toute mise à jour du voisinage.
        if all_value == 0 and interface_value == 0:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unsolicited_arp_learning(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui créent des voisins depuis des ARP non sollicités."""
    try:
        with open(os.path.join(root, "all", "arp_accept"), encoding="utf-8") as f:
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
                os.path.join(root, interface, "arp_accept"), encoding="utf-8"
            ) as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # arp.c consulte IN_DEV_ARP_ACCEPT, défini comme IN_DEV_MAXCONF :
        # la valeur effective est le maximum entre "all" et l'interface.
        effective = max(all_value, interface_value)
        if effective in (1, 2):
            findings.append((interface, all_value, interface_value, effective))
    return findings


def scan_unicast_ipv4_in_l2_multicast(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces acceptant un paquet IPv4 unicast dans une trame L2 multicast."""
    try:
        with open(
            os.path.join(root, "all", "drop_unicast_in_l2_multicast"),
            encoding="utf-8",
        ) as f:
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
                os.path.join(root, interface, "drop_unicast_in_l2_multicast"),
                encoding="utf-8",
            ) as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # ip_input.c utilise IN_DEV_ORCONF : la politique globale OU locale
        # suffit à jeter cette incohérence entre les destinations L2 et L3.
        if all_value == 0 and interface_value == 0:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unsafe_ipv6_source_routing(root="/proc/sys/net/ipv6/conf"):
    """Liste les interfaces qui acceptent l'en-tete de routage IPv6 type 2."""
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
        # Le kernel prend le minimum entre la politique globale et locale :
        # toute valeur negative refuse les routing headers, sinon seul le type 2 passe.
        if all_value >= 0 and interface_value >= 0:
            findings.append((interface, all_value, interface_value))
    return findings


def scan_unauthenticated_srv6_interfaces(root="/proc/sys/net/ipv6/conf"):
    """Liste les interfaces acceptant des paquets SRv6 sans HMAC obligatoire."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        # Ces réglages sont propres à chaque interface. "all" et "default"
        # ne prouvent pas qu'un paquet est accepté, et le loopback n'est pas une
        # surface réseau distante.
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "seg6_enabled"), encoding="utf-8") as f:
                enabled = int(f.read().strip())
            with open(
                os.path.join(root, interface, "seg6_require_hmac"), encoding="utf-8"
            ) as f:
                hmac_policy = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # La documentation upstream définit toute valeur non nulle comme active.
        # Seul le mode HMAC 1 refuse les paquets SRv6 dépourvus de HMAC.
        if enabled != 0 and hmac_policy != 1:
            findings.append((interface, enabled, hmac_policy))
    return findings


def scan_wifi_accepting_unsolicited_ipv6_na(
    sysctl_root="/proc/sys/net/ipv6/conf",
    net_root="/sys/class/net",
):
    """Liste les interfaces Wi-Fi qui ne jettent pas les NA IPv6 non sollicitees."""
    try:
        interfaces = os.listdir(sysctl_root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        # Le dossier wireless de sysfs identifie une interface 802.11 sans
        # deviner son nom (wlan*, wlp*, etc.). La politique est locale à l'interface.
        if not os.path.isdir(os.path.join(net_root, interface, "wireless")):
            continue
        try:
            with open(
                os.path.join(sysctl_root, interface, "drop_unsolicited_na"),
                encoding="utf-8",
            ) as f:
                value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        if value == 0:
            findings.append((interface, value))
    return findings


def scan_ipv6_routers_learning_untracked_neighbors(
    root="/proc/sys/net/ipv6/conf",
):
    """Liste les routeurs IPv6 apprenant des voisins absents de leur cache."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            values = {}
            for name in ("accept_untracked_na", "forwarding", "drop_unsolicited_na"):
                with open(os.path.join(root, interface, name), encoding="utf-8") as f:
                    values[name] = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # Ce mécanisme est destiné aux routeurs RFC 9131. La documentation du
        # kernel donne à drop_unsolicited_na une priorité supérieure : si ce
        # dernier vaut 1, le mode d'apprentissage n'est pas effectif.
        if (
            values["forwarding"] == 1
            and values["accept_untracked_na"] in (1, 2)
            and values["drop_unsolicited_na"] == 0
        ):
            findings.append((interface, values["accept_untracked_na"]))
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


def scan_locally_sourced_ipv4_interfaces(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces acceptant des paquets dont la source est locale."""
    try:
        with open(os.path.join(root, "all", "accept_local"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "accept_local"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        # IN_DEV_ACCEPT_LOCAL utilise IN_DEV_ORCONF : la politique globale OU
        # celle de l'interface suffit à accepter une adresse source locale.
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


def scan_broad_ipv4_redirect_trust(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui acceptent des redirects sans limiter la passerelle.

    shared_media effectif outrepasse secure_redirects, meme si ce dernier vaut 1.
    Sans shared_media, secure_redirects doit etre effectif pour limiter les redirects
    aux passerelles deja connues de l'interface.
    """
    try:
        def read_global(name):
            with open(os.path.join(root, "all", name), encoding="utf-8") as f:
                return int(f.read().strip())

        accept_all = read_global("accept_redirects")
        shared_all = read_global("shared_media")
        secure_all = read_global("secure_redirects")
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            values = []
            for name in ("accept_redirects", "forwarding", "shared_media", "secure_redirects"):
                with open(os.path.join(root, interface, name), encoding="utf-8") as f:
                    values.append(int(f.read().strip()))
        except (OSError, ValueError):
            continue

        accept_local, forwarding, shared_local, secure_local = values
        accepts = (
            accept_all == 1 and accept_local == 1
            if forwarding == 1
            else accept_all == 1 or accept_local == 1
        )
        shared_effective = shared_all == 1 or shared_local == 1
        secure_effective = secure_all == 1 or secure_local == 1
        if accepts and (shared_effective or not secure_effective):
            findings.append(
                (interface, shared_all, shared_local, secure_all, secure_local)
            )
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


def scan_directed_broadcast_forwarders(root="/proc/sys/net/ipv4/conf"):
    """Liste les interfaces qui relaient effectivement les broadcasts diriges."""
    try:
        with open(os.path.join(root, "all", "bc_forwarding"), encoding="utf-8") as f:
            all_value = int(f.read().strip())
        interfaces = os.listdir(root)
    except (OSError, ValueError):
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            with open(os.path.join(root, interface, "bc_forwarding"), encoding="utf-8") as f:
                interface_value = int(f.read().strip())
            with open(os.path.join(root, interface, "forwarding"), encoding="utf-8") as f:
                forwarding = int(f.read().strip())
        except (OSError, ValueError):
            continue

        # Le kernel exige le verrou global ET celui de l'interface d'entree.
        # Le forwarding local confirme que l'interface joue bien le role routeur.
        if all_value == 1 and interface_value == 1 and forwarding == 1:
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


def scan_ipv6_local_router_advertisements(root="/proc/sys/net/ipv6/conf"):
    """Liste les interfaces acceptant une RA dont la source est locale."""
    try:
        interfaces = os.listdir(root)
    except OSError:
        return []

    findings = []
    for interface in sorted(interfaces):
        if interface in ("all", "default", "lo"):
            continue
        try:
            values = []
            for name in ("accept_ra", "forwarding", "accept_ra_from_local"):
                with open(os.path.join(root, interface, name), encoding="utf-8") as f:
                    values.append(int(f.read().strip()))
        except (OSError, ValueError):
            continue

        accept_ra, forwarding, accept_from_local = values
        # accept_ra=1 n'est fonctionnel qu'en mode hote ; le mode 2 force
        # l'acceptation meme sur un routeur. Ce reglage est propre a l'interface.
        ra_enabled = accept_ra == 2 or (accept_ra == 1 and forwarding == 0)
        if accept_from_local == 1 and ra_enabled:
            findings.append((interface, accept_ra, forwarding, accept_from_local))
    return findings


def scan_forwarded_protocol_pmtu_trust(
    forwarding_path="/proc/sys/net/ipv4/ip_forward",
    policy_path="/proc/sys/net/ipv4/ip_forward_use_pmtu",
):
    """Retourne le couple actif quand un routeur fait confiance aux PMTU de protocole."""
    try:
        values = []
        for path in (forwarding_path, policy_path):
            with open(path, encoding="utf-8") as f:
                values.append(int(f.read().strip()))
    except (OSError, ValueError):
        return None

    forwarding, use_pmtu = values
    # Cette politique n'agit que sur les paquets forwardés. Le kernel la laisse
    # désactivée par défaut, car une PMTU apprise par le protocole se forge
    # facilement et peut forcer le routeur à fragmenter inutilement le trafic.
    return (forwarding, use_pmtu) if forwarding == 1 and use_pmtu == 1 else None


def scan_disabled_invalid_tcp_ratelimit(
    path="/proc/sys/net/ipv4/tcp_invalid_ratelimit",
):
    """Retourne 0 quand les ACK aux segments TCP invalides ne sont pas limites."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # Toute valeur positive impose un délai minimal en millisecondes entre les
    # ACK dupliqués. Seul 0 désactive explicitement le limiteur documenté.
    return value if value == 0 else None


def scan_tcp_challenge_ack_side_channel(
    path="/proc/sys/net/ipv4/tcp_challenge_ack_limit",
):
    """Retourne une limite globale de Challenge ACK active dans le netns."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # La documentation kernel déconseille ce budget partagé par namespace :
    # son épuisement est observable et crée un canal auxiliaire. INT_MAX est la
    # valeur upstream « unlimited » ; les limites par socket restent actives.
    return value if 0 <= value < 2147483647 else None


def scan_tcp_timewait_assassination(path="/proc/sys/net/ipv4/tcp_rfc1337"):
    """Retourne 0 lorsque les RST peuvent supprimer prématurément TIME-WAIT."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_tcp_timestamp_uptime_leak(path="/proc/sys/net/ipv4/tcp_timestamps"):
    """Retourne 2 lorsque les timestamps TCP sont émis sans offset aléatoire."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # Le mode 1 randomise l'origine par connexion. Le mode 2 conserve les
    # timestamps mais retire cet offset ; 0 désactive entièrement l'option.
    return value if value == 2 else None


def scan_broadcast_icmp_echo_enabled(
    path="/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
):
    """Retourne 0 si Linux répond aux requêtes ICMP broadcast/multicast."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_empty_icmp_ratemask(path="/proc/sys/net/ipv4/icmp_ratemask"):
    """Retourne 0 quand aucun type ICMP n'est soumis aux limiteurs du kernel."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip(), 0)
    except (OSError, ValueError):
        return None
    # icmpv4_mask_allow() laisse immédiatement passer un type dont le bit est
    # absent. Un masque nul contourne donc les limiteurs global et par cible,
    # quelles que soient les valeurs de icmp_msgs_per_sec et icmp_ratelimit.
    return value if value == 0 else None


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

        ipsec_bypass = scan_ipv4_ipsec_bypass_interfaces()
        if ipsec_bypass:
            interfaces = ", ".join(
                f"{interface} (policy={disable_policy}, xfrm={disable_xfrm})"
                for interface, disable_policy, disable_xfrm in ipsec_bypass
            )
            m.add(
                "Exception IPsec active sur une interface IPv4",
                f"Interfaces concernees : {interfaces}. disable_policy=1 retire la politique SPD et disable_xfrm=1 coupe les transformations IPsec quelle que soit la politique. Ce constat ne prouve pas qu'un tunnel IPsec est configure ; verifier les politiques XFRM et documenter toute exception de conteneur ou de tunnel.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{default,*/}{disable_policy,disable_xfrm} 2>/dev/null; ip -4 xfrm policy; ip -4 xfrm state",
            )

        gratuitous_arp = scan_gratuitous_arp_updates()
        if gratuitous_arp:
            interfaces = ", ".join(item[0] for item in gratuitous_arp)
            m.add(
                "Mises a jour par ARP gratuitous acceptees",
                f"Interfaces concernees : {interfaces}. Une annonce ARP gratuite peut encore remplacer une entree existante du cache voisin, meme avec arp_accept=0. Activer drop_gratuitous_arp seulement sur un reseau statique qui n'utilise ni bascule IP, ni mobilite, ni proxy ARP.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/drop_gratuitous_arp 2>/dev/null; ip -4 neigh show",
            )

        unsolicited_arp = scan_unsolicited_arp_learning()
        if unsolicited_arp:
            interfaces = ", ".join(
                f"{interface} (mode {effective})"
                for interface, _, _, effective in unsolicited_arp
            )
            m.add(
                "Apprentissage de voisins par ARP non sollicite",
                f"arp_accept est effectif sur : {interfaces}. Le mode 1 peut creer une entree voisine depuis toute annonce ARP gratuite inconnue ; le mode 2 la limite au sous-reseau local. Conserver 0 sauf besoin HA, mobilite ou proxy ARP documente.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/arp_accept 2>/dev/null; ip -4 neigh show",
            )

        l2_multicast_unicast = scan_unicast_ipv4_in_l2_multicast()
        if l2_multicast_unicast:
            interfaces = ", ".join(item[0] for item in l2_multicast_unicast)
            m.add(
                "IPv4 unicast accepte dans des trames L2 multicast",
                f"Interfaces concernees : {interfaces}. Une trame Ethernet ou Wi-Fi broadcast/multicast peut transporter une destination IP unicast et atteindre la pile locale ; le rejet est recommande par RFC 1122 et limite notamment l'usurpation entre clients Wi-Fi.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/drop_unicast_in_l2_multicast 2>/dev/null",
            )

        ipv6_source_routing = scan_unsafe_ipv6_source_routing()
        if ipv6_source_routing:
            interfaces = ", ".join(item[0] for item in ipv6_source_routing)
            m.add(
                "Extension de routage IPv6 type 2 acceptee",
                f"accept_source_route est non negatif globalement et sur : {interfaces}. Linux refuse les autres types mais accepte encore le type 2 lie a Mobile IPv6 ; passer la politique globale ou locale a -1 sauf besoin documente.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv6/conf/{all,default,*}/accept_source_route 2>/dev/null",
            )

        unauthenticated_srv6 = scan_unauthenticated_srv6_interfaces()
        if unauthenticated_srv6:
            interfaces = ", ".join(
                f"{interface} (HMAC={hmac_policy})"
                for interface, _, hmac_policy in unauthenticated_srv6
            )
            m.add(
                "Paquets SRv6 acceptes sans HMAC obligatoire",
                f"Interfaces concernees : {interfaces}. seg6_enabled accepte les paquets IPv6 avec Segment Routing Header destines a l'hote, tandis que seg6_require_hmac != 1 laisse aussi passer ceux sans HMAC. Desactiver SRv6 si inutile, ou exiger le HMAC apres validation des pairs et des cles.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}/{seg6_enabled,seg6_require_hmac} 2>/dev/null; ip -6 route show",
            )

        wifi_unsolicited_na = scan_wifi_accepting_unsolicited_ipv6_na()
        if wifi_unsolicited_na:
            interfaces = ", ".join(item[0] for item in wifi_unsolicited_na)
            m.add(
                "Annonces de voisin IPv6 non sollicitees acceptees en Wi-Fi",
                f"Interfaces concernees : {interfaces}. Le kernel recommande de jeter ces Neighbor Advertisements sur 802.11 pour empecher qu'un voisin injecte une association IPv6/MAC non sollicitee. Activer drop_unsolicited_na uniquement sur les interfaces Wi-Fi apres verification des proxies NDP ou mecanismes HA.",
                "LOW",
                verify="for i in /sys/class/net/*/wireless; do n=${i%/wireless}; n=${n##*/}; grep -H . /proc/sys/net/ipv6/conf/$n/drop_unsolicited_na; done",
            )

        untracked_ipv6_neighbors = scan_ipv6_routers_learning_untracked_neighbors()
        if untracked_ipv6_neighbors:
            interfaces = ", ".join(
                f"{interface} (mode {mode})"
                for interface, mode in untracked_ipv6_neighbors
            )
            m.add(
                "Apprentissage de voisins IPv6 absents du cache",
                f"Interfaces routeur concernees : {interfaces}. accept_untracked_na autorise une Neighbor Advertisement, meme non sollicitee, a creer une entree STALE qui n'existait pas ; le mode 2 exige au moins une source du meme sous-reseau. Conserver 0 sauf optimisation RFC 9131 documentee avec ndisc_notify ; drop_unsolicited_na=1 neutralise ce mecanisme.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}{accept_untracked_na,drop_unsolicited_na,forwarding} 2>/dev/null; ip -6 neigh show",
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

        locally_sourced = scan_locally_sourced_ipv4_interfaces()
        if locally_sourced:
            interfaces = ", ".join(item[0] for item in locally_sourced)
            m.add(
                "Paquets a source IPv4 locale acceptes depuis le reseau",
                f"accept_local est effectif sur : {interfaces}. Un paquet recu peut usurper une adresse que l'hote considere locale ; ce mode sert a certains routages asymetriques, mais doit rester desactive sans besoin documente.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/accept_local 2>/dev/null; ip route show table all",
            )

        redirect_findings = scan_unsafe_ipv4_redirects()
        broad_redirect_trust = scan_broad_ipv4_redirect_trust()
        if redirect_findings:
            interfaces = ", ".join(item[0] for item in redirect_findings)
            broad_by_interface = {item[0]: item for item in broad_redirect_trust}
            broad_interfaces = sorted(
                {item[0] for item in redirect_findings} & set(broad_by_interface)
            )
            shared_interfaces = [
                interface for interface in broad_interfaces
                if broad_by_interface[interface][1] == 1
                or broad_by_interface[interface][2] == 1
            ]
            unrestricted_interfaces = [
                interface for interface in broad_interfaces
                if interface not in shared_interfaces
            ]
            trust_notes = []
            if shared_interfaces:
                trust_notes.append(
                    f"Sur {', '.join(shared_interfaces)}, shared_media outrepasse secure_redirects : la passerelle proposee n'est pas limitee aux passerelles deja connues."
                )
            if unrestricted_interfaces:
                trust_notes.append(
                    f"Sur {', '.join(unrestricted_interfaces)}, secure_redirects est inactif : la passerelle proposee n'est pas limitee aux passerelles deja connues."
                )
            trust_note = f" {' '.join(trust_notes)}" if trust_notes else ""
            m.add(
                "Acceptation effective des redirects ICMP IPv4",
                f"Interfaces concernees : {interfaces}. Sur un hote, une valeur locale a 1 suffit meme si conf/all vaut 0 ; un voisin reseau peut alors tenter de modifier la route utilisee.{trust_note} Desactiver apres verification des besoins de routage.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*}/{accept_redirects,forwarding,shared_media,secure_redirects} 2>/dev/null",
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

        directed_broadcasts = scan_directed_broadcast_forwarders()
        if directed_broadcasts:
            interfaces = ", ".join(item[0] for item in directed_broadcasts)
            m.add(
                "Forwarding de broadcast dirige IPv4 actif",
                f"Interfaces routeur concernees : {interfaces}. bc_forwarding vaut 1 globalement et localement : un paquet unicast vers l'adresse broadcast d'un sous-reseau peut etre relaye a tous ses hotes et servir d'amplification. Conserver 0 sauf besoin reseau historique explicitement filtre.",
                "MEDIUM",
                verify="grep -H . /proc/sys/net/ipv4/conf/{all,default,*/}{bc_forwarding,forwarding} 2>/dev/null",
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
        ipv6_local_ra = scan_ipv6_local_router_advertisements()
        if ipv6_routers_accepting_ra:
            interfaces = ", ".join(item[0] for item in ipv6_routers_accepting_ra)
            local_sources = {item[0] for item in ipv6_local_ra}
            overlap = sorted({item[0] for item in ipv6_routers_accepting_ra} & local_sources)
            local_note = (
                f" accept_ra_from_local=1 accepte aussi une source appartenant a la machine sur : {', '.join(overlap)}."
                if overlap else ""
            )
            m.add(
                "Routeur acceptant les Router Advertisements IPv6",
                f"Interfaces concernees : {interfaces}. accept_ra=2 outrepasse le mode routeur : un voisin peut encore fournir une route ou des prefixes IPv6.{local_note} Garder ce mode seulement pour un routeur qui doit aussi apprendre sa connectivite par RA.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}{accept_ra,accept_ra_from_local,forwarding} 2>/dev/null",
            )

        router_interfaces = {item[0] for item in ipv6_routers_accepting_ra}
        local_only = [item for item in ipv6_local_ra if item[0] not in router_interfaces]
        if local_only:
            interfaces = ", ".join(item[0] for item in local_only)
            m.add(
                "Annonces IPv6 a source locale acceptees",
                f"Interfaces concernees : {interfaces}. Linux refuse normalement une RA dont l'adresse source appartient deja a la machine pour eviter une boucle reseau involontaire ; conserver accept_ra_from_local=1 uniquement pour un montage documente.",
                "LOW",
                verify="grep -H . /proc/sys/net/ipv6/conf/{default,*/}{accept_ra,accept_ra_from_local,forwarding} 2>/dev/null",
            )

        if scan_forwarded_protocol_pmtu_trust() == (1, 1):
            m.add(
                "Routeur faisant confiance aux PMTU de protocole",
                "net.ipv4.ip_forward = 1 et net.ipv4.ip_forward_use_pmtu = 1 : le routeur accepte des informations de taille de chemin facilement forgeables, ce qui peut lui imposer une fragmentation indesirable. Conserver 0 sauf logiciel user-space de decouverte PMTU qui exige explicitement cette confiance.",
                "LOW",
                verify="sysctl net.ipv4.ip_forward net.ipv4.ip_forward_use_pmtu",
            )

        # Un segment hors fenêtre, un ACK hors fenêtre ou un échec PAWS peut
        # provoquer un ACK dupliqué. Sans délai, deux extrémités manipulées par
        # un middlebox peuvent s'entretenir mutuellement dans une boucle d'ACK.
        if scan_disabled_invalid_tcp_ratelimit() == 0:
            m.add(
                "Boucles d'acquittements TCP sans limite",
                "net.ipv4.tcp_invalid_ratelimit = 0 : les ACK dupliques envoyes en reponse aux segments invalides partent sans limite temporelle. Un middlebox defectueux ou malveillant peut alors entretenir une boucle d'ACK et consommer bande passante et CPU ; utiliser une valeur positive mesuree, 500 ms etant la valeur upstream.",
                "LOW",
                verify="sysctl net.ipv4.tcp_invalid_ratelimit",
            )

        challenge_ack_limit = scan_tcp_challenge_ack_side_channel()
        if challenge_ack_limit is not None:
            zero_note = (
                " La valeur 0 supprime aussi les Challenge ACK protecteurs."
                if challenge_ack_limit == 0 else ""
            )
            m.add(
                "Budget partage de Challenge ACK TCP actif",
                f"net.ipv4.tcp_challenge_ack_limit = {challenge_ack_limit} : ce quota par namespace est observable lorsqu'il est epuise et peut servir de canal auxiliaire a une attaque TCP hors chemin.{zero_note} Le kernel recommande INT_MAX (2147483647), car les limites par socket restent appliquees.",
                "LOW",
                verify="sysctl net.ipv4.tcp_challenge_ack_limit",
            )

        # Le chemin effectif du kernel supprime l'etat TIME-WAIT sur un RST
        # en fenetre lorsque tcp_rfc1337=0. Le mode 1 ignore ce RST, comme le
        # correctif F1 du RFC 1337, afin que les anciens segments expirent.
        if scan_tcp_timewait_assassination() == 0:
            m.add(
                "Protection TCP TIME-WAIT contre les RST desactivee",
                "net.ipv4.tcp_rfc1337 = 0 : un RST valide peut supprimer prematurement l'etat TIME-WAIT et laisser d'anciens segments perturber une connexion reutilisant les memes adresses et ports. Le mode 1 conserve TIME-WAIT face a ce RST.",
                "LOW",
                verify="sysctl net.ipv4.tcp_rfc1337",
            )

        # tcp_timestamps=2 n'est pas un mode « renforcé » : il conserve les
        # timestamps RFC 1323 mais retire l'offset aléatoire propre à chaque
        # connexion, ce qui facilite l'estimation distante de l'uptime.
        if scan_tcp_timestamp_uptime_leak() == 2:
            m.add(
                "Horodatages TCP emis sans randomisation",
                "net.ipv4.tcp_timestamps = 2 : Linux emet les horodatages TCP sans decalage aleatoire par connexion, ce qui facilite l'estimation distante de l'uptime et le fingerprinting. Utiliser 1 pour conserver PAWS avec randomisation, sauf besoin de diagnostic documente.",
                "LOW",
                verify="sysctl net.ipv4.tcp_timestamps",
            )

        # La documentation kernel confirme que le mode 1 ignore les requêtes
        # ECHO et TIMESTAMP reçues via broadcast ou multicast. Le mode 0 peut
        # donc faire participer l'hôte à une amplification ICMP locale.
        if scan_broadcast_icmp_echo_enabled() == 0:
            m.add(
                "Reponses ICMP aux adresses broadcast/multicast actives",
                "net.ipv4.icmp_echo_ignore_broadcasts = 0 : Linux repond aux requetes ECHO et TIMESTAMP envoyees en broadcast ou multicast. Une source usurpee peut alors transformer les hotes du segment en amplification vers une victime ; conserver la valeur 1 sauf besoin de diagnostic exceptionnel.",
                "MEDIUM",
                verify="sysctl net.ipv4.icmp_echo_ignore_broadcasts",
            )

        # Les deux limiteurs ICMP ne s'appliquent qu'aux types dont le bit est
        # present dans icmp_ratemask. Un masque nul les contourne donc tous,
        # meme si leurs valeurs numeriques semblent restrictives.
        if scan_empty_icmp_ratemask() == 0:
            m.add(
                "Limitation ICMP neutralisee par un masque vide",
                "net.ipv4.icmp_ratemask = 0 : aucun type ICMP n'est soumis au limiteur global ni au limiteur par destination. Restaurer un masque non nul adapte aux types d'erreur attendus ; la valeur upstream 6168 couvre notamment destination unreachable, time exceeded et parameter problem.",
                "LOW",
                verify="sysctl net.ipv4.icmp_ratemask net.ipv4.icmp_msgs_per_sec net.ipv4.icmp_msgs_burst net.ipv4.icmp_ratelimit",
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
        # Le mode 1 ne couvre que les repertoires sticky world-writable. Le
        # mode 2 etend O_CREAT aux repertoires sticky group-writable.
        "protected_fifos": (2, "FIFO insuffisamment proteges"),
        "protected_regular": (2, "Fichiers reguliers insuffisamment proteges"),
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


def scan_exposed_kernel_debug_mounts(mountinfo_path="/proc/self/mountinfo"):
    """Retourne les montages debugfs/tracefs accessibles hors de root."""
    try:
        with open(mountinfo_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []

    findings = []
    seen = set()
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 1 or fields[separator + 1] not in {"debugfs", "tracefs"}:
            continue
        mountpoint = (fields[4].replace("\\040", " ").replace("\\011", "\t")
                      .replace("\\012", "\n").replace("\\134", "\\"))
        if mountpoint in seen:
            continue
        seen.add(mountpoint)
        try:
            info = os.stat(mountpoint)
        except OSError:
            continue
        mode = stat.S_IMODE(info.st_mode)
        # La documentation upstream rend la racine debugfs accessible uniquement
        # à root par défaut. Tout bit groupe/autres élargit explicitement l'accès.
        if info.st_uid != 0 or mode & 0o077:
            findings.append((fields[separator + 1], mountpoint, mode, info.st_uid, info.st_gid))
    return findings


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


def scan_unsafe_core_pipe_helper(core_pattern_path="/proc/sys/kernel/core_pattern"):
    """Retourne le premier composant non-root ou inscriptible d'un helper core pipe."""
    try:
        with open(core_pattern_path, encoding="utf-8") as f:
            pattern = f.read().strip()
    except OSError:
        return None
    if not pattern.startswith("|"):
        return None

    command = pattern[1:].lstrip()
    if not command:
        return None
    helper = command.split(None, 1)[0]
    if not os.path.isabs(helper):
        return None

    resolved = os.path.realpath(helper)
    current = "/"
    for component in resolved.strip("/").split("/"):
        current = os.path.join(current, component)
        try:
            info = os.stat(current)
        except OSError:
            return None
        mode = stat.S_IMODE(info.st_mode)
        # Le kernel lance ce helper avec les credentials root dans les
        # namespaces initiaux : tout son chemin doit rester maitrise par root.
        if info.st_uid != 0 or mode & 0o022:
            return helper, current, mode, info.st_uid, info.st_gid
    return None


def scan_unsafe_module_helper(path="/proc/sys/kernel/modprobe"):
    """Retourne le premier composant non-root ou inscriptible du helper modprobe."""
    try:
        with open(path, encoding="utf-8") as f:
            helper = f.read().strip()
    except OSError:
        return None
    # Une valeur vide desactive completement l'autoload selon la documentation
    # du kernel. Une valeur non absolue ne peut pas designer le helper attendu.
    if not helper or not os.path.isabs(helper):
        return None

    resolved = os.path.realpath(helper)
    current = "/"
    for component in resolved.strip("/").split("/"):
        current = os.path.join(current, component)
        try:
            info = os.stat(current)
        except OSError:
            return None
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0 or mode & 0o022:
            return helper, current, mode, info.st_uid, info.st_gid
    return None


def scan_enabled_hotplug_helper(path="/proc/sys/kernel/hotplug"):
    """Retourne le helper uevent actif et son premier composant de chemin faible.

    Une valeur vide desactive l'ancien helper lance pour chaque uevent. Un
    chemin actif reste visible meme s'il est correctement protege, car les
    kernels modernes utilisent normalement le canal netlink.
    """
    try:
        with open(path, encoding="utf-8") as f:
            helper = f.read().strip()
    except OSError:
        return None
    if not helper:
        return None

    if os.path.isabs(helper):
        resolved = os.path.realpath(helper)
        current = "/"
        for component in resolved.strip("/").split("/"):
            current = os.path.join(current, component)
            try:
                info = os.stat(current)
            except OSError:
                break
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != 0 or mode & 0o022:
                return helper, current, mode, info.st_uid, info.st_gid
    return helper, None, None, None, None


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


def scan_disabled_perf_cpu_throttle(
    path="/proc/sys/kernel/perf_cpu_time_max_percent",
):
    """Retourne 0 lorsque perf ne limite plus le temps CPU de l'échantillonnage."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # La documentation kernel définit 0 comme la désactivation du mécanisme ;
    # toute valeur de 1 à 100 conserve une forme de limitation adaptative.
    return value if value == 0 else None


def scan_unrestricted_io_uring(path="/proc/sys/kernel/io_uring_disabled"):
    """Retourne 0 lorsque tous les utilisateurs peuvent creer une instance io_uring."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_io_uring_group_delegation(
    io_uring_path="/proc/sys/kernel/io_uring_disabled",
    group_path="/proc/sys/kernel/io_uring_group",
):
    """Retourne le GID autorise a creer des io_uring lorsque le mode 1 est actif."""
    try:
        with open(io_uring_path, encoding="utf-8") as f:
            policy = int(f.read().strip())
        with open(group_path, encoding="utf-8") as f:
            group_id = int(f.read().strip())
    except (OSError, ValueError):
        return None
    # En mode 1, -1 reserve la creation a CAP_SYS_ADMIN. Un GID positif est
    # une delegation explicite qui merite d'etre visible, sans etre penalisee.
    return group_id if policy == 1 and group_id >= 0 else None


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


def scan_unlimited_kexec_loads(
    reboot_path="/proc/sys/kernel/kexec_load_limit_reboot",
    panic_path="/proc/sys/kernel/kexec_load_limit_panic",
):
    """Liste les types d'image kexec dont le nombre de chargements est illimite.

    Ces compteurs ne peuvent qu'etre rendus plus restrictifs. Leur absence est
    traitee comme une fonctionnalite kernel indisponible, pas comme une faiblesse.
    """
    unlimited = []
    readable = False
    for image_type, path in (("reboot", reboot_path), ("panic", panic_path)):
        try:
            with open(path, encoding="utf-8") as f:
                value = int(f.read().strip())
        except (OSError, ValueError):
            continue
        readable = True
        if value == -1:
            unlimited.append(image_type)
    return tuple(unlimited) if readable else None


def scan_module_loading_unlocked(path="/proc/sys/kernel/modules_disabled"):
    """Retourne 0 si le chargement et le retrait de modules restent autorises."""
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip())
    except (OSError, ValueError):
        return None
    return value if value == 0 else None


def scan_permissive_module_signatures(
    config_path=None,
    cmdline_path="/proc/cmdline",
    modules_disabled_path="/proc/sys/kernel/modules_disabled",
    lockdown_path="/sys/kernel/security/lockdown",
):
    """Détecte les modules chargeables sans signature valide obligatoire.

    Un verrou global des modules, CONFIG_MODULE_SIG_FORCE, le paramètre de boot
    module.sig_enforce=1 ou un mode Lockdown actif ferment chacun cette voie.
    Si l'une des preuves nécessaires est illisible, le résultat reste inconnu.
    """
    if config_path is None:
        config_path = f"/boot/config-{os.uname().release}"
    try:
        with open(modules_disabled_path, encoding="utf-8") as policy:
            modules_disabled = int(policy.read().strip())
        with open(config_path, encoding="utf-8") as config:
            options = {
                line.split("=", 1)[0]: line.split("=", 1)[1].strip()
                for line in config
                if line.startswith("CONFIG_MODULE_SIG") and "=" in line
            }
        with open(cmdline_path, encoding="utf-8") as cmdline:
            parameters = set(cmdline.read().split())
        with open(lockdown_path, encoding="utf-8") as lockdown:
            lockdown_status = lockdown.read().split()
    except (OSError, ValueError):
        return None

    if modules_disabled != 0:
        return None
    if options.get("CONFIG_MODULE_SIG_FORCE") == "y":
        return None
    if "module.sig_enforce=1" in parameters:
        return None
    active_lockdown = next(
        (mode.strip("[]") for mode in lockdown_status if mode.startswith("[")),
        None,
    )
    if active_lockdown in {"integrity", "confidentiality"}:
        return None

    signature_support = options.get("CONFIG_MODULE_SIG") == "y"
    return "permissive" if signature_support else "unsupported"


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


def scan_legacy_apparmor_userns_bypass(
    userns_path="/proc/sys/kernel/unprivileged_userns_clone",
    restriction_path="/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    force_path="/proc/sys/kernel/apparmor_restrict_unprivileged_userns_force",
):
    """Détecte les anciennes ABI de politique exemptées de la médiation userns."""
    try:
        values = []
        for path in (userns_path, restriction_path, force_path):
            with open(path, encoding="utf-8") as f:
                values.append(int(f.read().strip()))
    except (OSError, ValueError):
        return None
    userns_enabled, apparmor_restricted, legacy_policy_forced = values
    if userns_enabled == 1 and apparmor_restricted == 1 and legacy_policy_forced == 0:
        return tuple(values)
    return None


def scan_suboptimal_aslr_entropy(
    bits_path="/proc/sys/vm/mmap_rnd_bits",
    compat_path="/proc/sys/vm/mmap_rnd_compat_bits",
    config_path=None,
):
    """Compare l'entropie ASLR mmap aux maxima compiles pour ce kernel."""
    if config_path is None:
        config_path = f"/boot/config-{os.uname().release}"
    try:
        with open(config_path, encoding="utf-8") as config:
            maximums = {}
            for line in config:
                if line.startswith("CONFIG_ARCH_MMAP_RND_BITS_MAX="):
                    maximums["vm.mmap_rnd_bits"] = int(line.split("=", 1)[1])
                elif line.startswith("CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX="):
                    maximums["vm.mmap_rnd_compat_bits"] = int(line.split("=", 1)[1])
    except (OSError, ValueError):
        return []

    weak = []
    for name, path in (
        ("vm.mmap_rnd_bits", bits_path),
        ("vm.mmap_rnd_compat_bits", compat_path),
    ):
        if name not in maximums:
            continue
        try:
            with open(path, encoding="utf-8") as current_file:
                current = int(current_file.read().strip())
        except (OSError, ValueError):
            continue
        if current < maximums[name]:
            weak.append((name, current, maximums[name]))
    return weak


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
    accepted_values = {
        # 1 active les cookies en cas de débordement du backlog SYN ; 2 les
        # génère sans condition pour tester leur impact. Aucun des deux modes
        # ne signifie que la protection est désactivée.
        "net.ipv4.tcp_syncookies": {"1", "2"},
    }
    if name in accepted_values:
        return value not in accepted_values[name]
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


def scan_unlimited_kernel_warnings(
    panic_path="/proc/sys/kernel/panic_on_warn",
    limit_path="/proc/sys/kernel/warn_limit",
):
    """Retourne la politique si le nombre de WARN ne peut jamais provoquer de panic."""
    try:
        with open(panic_path, encoding="utf-8") as f:
            panic_on_warn = int(f.read().strip())
        with open(limit_path, encoding="utf-8") as f:
            warn_limit = int(f.read().strip())
    except (OSError, ValueError):
        return None
    if panic_on_warn == 0 and warn_limit == 0:
        return panic_on_warn, warn_limit
    return None


def scan_disabled_hard_lockup_detector(
    path="/proc/sys/kernel/nmi_watchdog",
):
    """Retourne 0 si le detecteur NMI des blocages CPU durs est desactive."""
    try:
        with open(path, encoding="utf-8") as sysctl:
            value = int(sysctl.read().strip())
    except (OSError, ValueError):
        return None
    return 0 if value == 0 else None


def scan_disabled_hung_task_detector(
    path="/proc/sys/kernel/hung_task_timeout_secs",
):
    """Retourne 0 si le delai infini desactive la detection des taches bloquees."""
    try:
        with open(path, encoding="utf-8") as sysctl:
            value = int(sysctl.read().strip())
    except (OSError, ValueError):
        return None
    return 0 if value == 0 else None


def scan_silent_hung_task_detector(
    timeout_path="/proc/sys/kernel/hung_task_timeout_secs",
    warnings_path="/proc/sys/kernel/hung_task_warnings",
):
    """Retourne la politique si le detecteur actif n'emet plus d'avertissement."""
    try:
        with open(timeout_path, encoding="utf-8") as sysctl:
            timeout = int(sysctl.read().strip())
        with open(warnings_path, encoding="utf-8") as sysctl:
            warnings = int(sysctl.read().strip())
    except (OSError, ValueError):
        return None
    if timeout > 0 and warnings == 0:
        return timeout, warnings
    return None


def scan_destructive_magic_sysrq(path="/proc/sys/kernel/sysrq"):
    """Retourne les actions SysRq destructrices autorisees depuis le clavier.

    Le mode 1 active toutes les fonctions. Pour un masque, 0x40 autorise les
    signaux aux processus et 0x80 le redemarrage/extinction. L'interface root
    /proc/sysrq-trigger n'est volontairement pas concernee par ce sysctl.
    """
    try:
        with open(path, encoding="utf-8") as f:
            value = int(f.read().strip(), 0)
    except (OSError, ValueError):
        return None
    destructive = []
    if value == 1 or value & 0x40:
        destructive.append("signaux aux processus")
    if value == 1 or value & 0x80:
        destructive.append("redemarrage/extinction")
    return (value, destructive) if destructive else None


def scan_orphaned_sysv_shared_memory(
    table_path="/proc/sysvipc/shm",
    proc_root="/proc",
    min_age_seconds=3600,
    now=None,
):
    """Liste les segments SysV anciens, sans attache et dont le createur est mort.

    Un segment SysV peut survivre a son createur tant qu'IPC_RMID n'a pas ete
    demande. Le delai evite de signaler les tres courtes fenetres normales entre
    creation et attachement. Le test reste en lecture seule et propre au namespace
    IPC depuis lequel HardAudit est execute.
    """
    try:
        with open(table_path, encoding="utf-8") as table:
            header = table.readline().split()
            rows = [dict(zip(header, line.split())) for line in table if line.strip()]
    except OSError:
        return []

    required = {"shmid", "size", "cpid", "nattch", "uid", "ctime"}
    if not required.issubset(header):
        return []
    current_time = time.time() if now is None else now
    orphaned = []
    for row in rows:
        try:
            shmid = int(row["shmid"])
            size = int(row["size"])
            creator_pid = int(row["cpid"])
            attached = int(row["nattch"])
            owner_uid = int(row["uid"])
            created_at = int(row["ctime"])
        except (KeyError, ValueError):
            continue
        age = max(0, int(current_time - created_at))
        if (attached == 0 and age >= min_age_seconds
                and not os.path.exists(os.path.join(proc_root, str(creator_pid)))):
            orphaned.append({
                "shmid": shmid,
                "size": size,
                "creator_pid": creator_pid,
                "owner_uid": owner_uid,
                "age_seconds": age,
            })
    return orphaned


def scan_disabled_kstack_offset_randomization(config_path=None, cmdline_path="/proc/cmdline"):
    """Retourne la politique de boot si la pile kernel n'est pas randomisee."""
    if config_path is None:
        config_path = f"/boot/config-{os.uname().release}"
    try:
        with open(config_path, encoding="utf-8") as config:
            options = {
                line.split("=", 1)[0]: line.split("=", 1)[1].strip()
                for line in config
                if line.startswith("CONFIG_RANDOMIZE_KSTACK_OFFSET") and "=" in line
            }
        with open(cmdline_path, encoding="utf-8") as cmdline:
            parameters = cmdline.read().split()
    except OSError:
        return None

    # L'absence du support compile n'est pas appelee une mauvaise configuration.
    if options.get("CONFIG_RANDOMIZE_KSTACK_OFFSET") != "y":
        return None
    default_enabled = options.get("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT") == "y"

    true_values = {"1", "y", "yes", "true", "on"}
    false_values = {"0", "n", "no", "false", "off"}
    override = None
    enabled = default_enabled
    for parameter in parameters:
        if not parameter.startswith("randomize_kstack_offset="):
            continue
        value = parameter.split("=", 1)[1].lower()
        if value in true_values:
            enabled, override = True, value
        elif value in false_values:
            enabled, override = False, value
    return None if enabled else (default_enabled, override)


def scan_slab_cache_merging(config_path=None, cmdline_path="/proc/cmdline"):
    """Retourne True si le kernel fusionne par defaut les caches slab compatibles.

    Le parametre de boot ``slab_nomerge`` est la barriere runtime documentee.
    Sans configuration du kernel lisible, le contrôle reste inconnu plutot que
    de deduire une faiblesse depuis une simple absence dans la ligne de boot.
    """
    if config_path is None:
        config_path = f"/boot/config-{os.uname().release}"
    try:
        with open(config_path, encoding="utf-8") as config:
            default_merging = any(
                line.strip() == "CONFIG_SLAB_MERGE_DEFAULT=y" for line in config
            )
        with open(cmdline_path, encoding="utf-8") as cmdline:
            parameters = cmdline.read().split()
    except OSError:
        return None

    if not default_merging or "slab_nomerge" in parameters:
        return None
    return True


def scan_disabled_page_allocator_shuffle(
    path="/sys/module/page_alloc/parameters/shuffle",
):
    """Retourne l'etat si la randomisation des pages est disponible mais inactive.

    Le fichier runtime n'existe que lorsque le kernel expose cette fonctionnalite.
    Son absence reste donc inconnue plutot que d'etre assimilee a une faiblesse.
    """
    try:
        with open(path, encoding="utf-8") as status:
            value = status.read().strip()
    except OSError:
        return None
    return value if value.lower() in ("n", "0", "false", "off") else None


def scan_disabled_split_lock_mitigation(
    path="/proc/sys/kernel/split_lock_mitigate",
):
    """Retourne 0 si le kernel x86 expose mais n'applique pas cette mitigation."""
    try:
        with open(path, encoding="utf-8") as sysctl:
            value = int(sysctl.read().strip())
    except (OSError, ValueError):
        return None
    return 0 if value == 0 else None


def scan_disabled_cpu_mitigations(cmdline_path="/proc/cmdline"):
    """Retourne le parametre qui desactive globalement les mitigations CPU."""
    try:
        with open(cmdline_path, encoding="utf-8") as cmdline:
            parameters = cmdline.read().split()
    except OSError:
        return None
    # Le parametre est un token de boot exact. Une valeur absente equivaut a la
    # politique automatique du kernel ; ne pas faire correspondre une sous-chaine.
    return "mitigations=off" if "mitigations=off" in parameters else None


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

    # Les échantillons perf peuvent s'exécuter en NMI. Le kernel documente que
    # des NMI trop longues peuvent s'empiler jusqu'à empêcher tout autre travail ;
    # 0 désactive précisément le mécanisme qui réduit alors la fréquence.
    if scan_disabled_perf_cpu_throttle() == 0:
        m.add(
            "Limiteur CPU de l'echantillonnage perf desactive",
            "kernel.perf_cpu_time_max_percent = 0. Le kernel ne réduit plus la fréquence quand les échantillons perf consomment trop de CPU ; des NMI trop longues peuvent s'empiler et bloquer le reste du système. Utiliser une borne positive adaptée à l'observabilité.",
            "LOW",
            verify="sysctl kernel.perf_cpu_time_max_percent kernel.perf_event_paranoid",
        )

    # randomize_va_space=2 active l'ASLR, mais l'amplitude mmap reste reglable.
    # Comparer uniquement au maximum compile evite d'imposer une valeur qui ne
    # serait pas supportee par l'architecture ou ce kernel.
    for name, current, maximum in scan_suboptimal_aslr_entropy():
        path = "/proc/sys/" + name.replace(".", "/")
        config_key = (
            "CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX"
            if name.endswith("compat_bits") else
            "CONFIG_ARCH_MMAP_RND_BITS_MAX"
        )
        m.add(
            "Entropie ASLR mmap inferieure au maximum du kernel",
            f"{name} = {current} bits, alors que ce kernel accepte {maximum}. Augmenter progressivement jusqu'au maximum apres test des applications sensibles a l'espace d'adressage.",
            "LOW",
            verify=f"cat {path}; grep '^{config_key}={maximum}$' /boot/config-$(uname -r)",
        )

    kstack_policy = scan_disabled_kstack_offset_randomization()
    if kstack_policy is not None:
        _, override = kstack_policy
        reason = (
            f"le parametre de demarrage force la valeur {override!r}"
            if override is not None else
            "le kernel a ete compile avec cette protection inactive par defaut"
        )
        m.add(
            "Randomisation de la pile kernel desactivee",
            f"CONFIG_RANDOMIZE_KSTACK_OFFSET est disponible, mais {reason}. Cette protection ajoute environ 5 bits d'entropie a chaque entree syscall et complique les corruptions memoire qui dependent d'adresses de pile previsibles.",
            "LOW",
            verify="grep '^CONFIG_RANDOMIZE_KSTACK_OFFSET' /boot/config-$(uname -r); cat /proc/cmdline",
        )

    # Le kernel documente que slab_nomerge confine la plupart des effets d'une
    # attaque heap a un seul cache, au prix de davantage de memoire et d'une
    # moins bonne reutilisation du cache CPU.
    if scan_slab_cache_merging() is True:
        m.add(
            "Fusion des caches slab active",
            "CONFIG_SLAB_MERGE_DEFAULT est actif et slab_nomerge est absent de la ligne de demarrage. Des objets de sous-systemes differents peuvent partager un cache ; slab_nomerge reduit la plupart des effets d'une attaque heap a son cache d'origine, avec un cout memoire et de cache CPU.",
            "LOW",
            verify="grep '^CONFIG_SLAB_MERGE_DEFAULT=' /boot/config-$(uname -r); cat /proc/cmdline; find /sys/kernel/slab -maxdepth 1 -type l | head",
        )

    # Le kernel décrit ce mélange comme une optimisation de cache ayant aussi
    # un bénéfice de sécurité : les pages physiques deviennent moins prévisibles.
    # Il reste désactivé par défaut sans cache mémoire direct, car le forcer peut
    # pénaliser certaines charges ; le finding est donc informatif et contextuel.
    page_shuffle = scan_disabled_page_allocator_shuffle()
    if page_shuffle is not None:
        m.add(
            "Randomisation des pages memoire disponible mais inactive",
            f"/sys/module/page_alloc/parameters/shuffle = {page_shuffle}. La predictibilite des listes de pages libres reste plus forte ; page_alloc.shuffle=1 complete la randomisation slab, mais peut degrader les performances sur une plateforme sans cache memoire direct.",
            "LOW",
            verify="cat /sys/module/page_alloc/parameters/shuffle; grep '^CONFIG_SHUFFLE_PAGE_ALLOCATOR=' /boot/config-$(uname -r); cat /proc/cmdline",
        )

    # Sur x86, un split lock peut verrouiller le bus et penaliser tous les CPU.
    # Le mode 1 serialise et ralentit les processus fautifs ; l'absence du
    # sysctl signifie que la fonctionnalite n'est pas exposee, donc inconnue.
    if scan_disabled_split_lock_mitigation() == 0:
        m.add(
            "Mitigation des split locks desactivee",
            "kernel.split_lock_mitigate = 0. Un utilisateur non privilegie peut multiplier ces verrous couteux et imposer une forte penalite a tout le systeme ; le mode 1 serialise et ralentit les processus fautifs pour reduire ce deni de service.",
            "LOW",
            verify="sysctl kernel.split_lock_mitigate",
        )

    # Ce parametre unique est un interrupteur global documente par le kernel :
    # il desactive les protections CPU optionnelles choisies automatiquement.
    if scan_disabled_cpu_mitigations() == "mitigations=off":
        m.add(
            "Mitigations des vulnerabilites CPU desactivees au demarrage",
            "La ligne de demarrage contient mitigations=off. Ce seul parametre desactive les protections CPU optionnelles contre Spectre, MDS, L1TF, Retbleed et d'autres failles selon le processeur ; le retirer puis verifier chaque etat effectif apres redemarrage.",
            "HIGH",
            verify="cat /proc/cmdline; grep -H . /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null",
        )

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

    unsafe_core_helper = scan_unsafe_core_pipe_helper()
    if unsafe_core_helper is not None:
        helper, component, mode, uid, gid = unsafe_core_helper
        m.add(
            "Helper de core dump modifiable hors de root",
            f"kernel.core_pattern lance {helper}, mais {component} a les droits {mode:04o} et appartient a UID {uid}, GID {gid}. Le kernel execute ce helper avec les credentials root dans les namespaces initiaux : verrouiller tout son chemin a root.",
            "CRITICAL",
            verify="sysctl kernel.core_pattern; namei -l $(sysctl -n kernel.core_pattern | sed -n 's/^|[[:space:]]*\\([^[:space:]]*\\).*/\\1/p')",
        )

    unsafe_module_helper = scan_unsafe_module_helper()
    if unsafe_module_helper is not None:
        helper, component, mode, uid, gid = unsafe_module_helper
        m.add(
            "Helper d'autoload de modules modifiable hors de root",
            f"kernel.modprobe designe {helper}, mais {component} a les droits {mode:04o} et appartient a UID {uid}, GID {gid}. Le kernel peut executer ce helper avec les credentials root lorsqu'il demande un module : verrouiller tout son chemin a root.",
            "CRITICAL",
            verify="sysctl kernel.modprobe; namei -l $(sysctl -n kernel.modprobe)",
        )

    # CONFIG_UEVENT_HELPER permet au kernel de lancer ce programme pour chaque
    # evenement de peripherique. Les systemes modernes utilisent netlink et une
    # valeur vide ; un chemin actif ajoute donc une execution privilegiee et un
    # risque de tempete de processus, surtout si son chemin est modifiable.
    hotplug_helper = scan_enabled_hotplug_helper()
    if hotplug_helper is not None:
        helper, component, mode, uid, gid = hotplug_helper
        if component is not None:
            title = "Helper hotplug privilegie modifiable hors de root"
            detail = (
                f"kernel.hotplug designe {helper}, mais {component} a les droits "
                f"{mode:04o} et appartient a UID {uid}, GID {gid}. Chaque uevent peut "
                "alors lancer un programme substituable avec les credentials du kernel ; "
                "vider kernel.hotplug ou verrouiller tout le chemin a root."
            )
            severity = "CRITICAL"
        else:
            title = "Ancien helper hotplug kernel actif"
            detail = (
                f"kernel.hotplug designe {helper}. Le kernel peut lancer un processus "
                "pour chaque uevent alors que les systemes modernes utilisent netlink ; "
                "vider ce reglage sauf dependance embarquee explicitement verifiee."
            )
            severity = "LOW"
        m.add(
            title,
            detail,
            severity,
            verify="sysctl kernel.hotplug; helper=$(sysctl -n kernel.hotplug); [ -z \"$helper\" ] || namei -l \"$helper\"",
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

    # warn_limit=0 ne signifie pas tolerance zero : la documentation kernel dit
    # que cette valeur desactive le compteur. Une borne positive evite une suite
    # infinie de WARN sans imposer une indisponibilite au premier avertissement.
    if scan_unlimited_kernel_warnings() == (0, 0):
        m.add(
            "Warnings kernel repetables sans limite",
            "kernel.panic_on_warn = 0 et kernel.warn_limit = 0. La valeur 0 signifie compteur desactive : aucune accumulation de WARN ne declenchera de panic. Utiliser une borne positive dimensionnee apres avoir corrige les warnings legitimes ; panic_on_warn=1 peut transformer le premier bug en indisponibilite.",
            "LOW",
            verify="sysctl kernel.panic_on_warn kernel.warn_limit",
        )

    # kernel.watchdog est un OU logique : il peut afficher 1 uniquement parce
    # que le detecteur soft est actif. Seul nmi_watchdog confirme le detecteur
    # hard, capable d'interrompre un CPU qui ne traite plus les timers normaux.
    if scan_disabled_hard_lockup_detector() == 0:
        m.add(
            "Detecteur de hard lockup CPU desactive",
            "kernel.nmi_watchdog = 0. Le watchdog soft peut rester actif et faire afficher kernel.watchdog = 1, mais il depend encore des interruptions timer ; seul le watchdog NMI detecte un CPU completement bloque. L'activer apres validation des compteurs de performance et de l'hyperviseur.",
            "LOW",
            verify="sysctl kernel.watchdog kernel.soft_watchdog kernel.nmi_watchdog",
        )

    # Le zero n'est pas une detection immediate : la documentation kernel le
    # definit comme un delai infini, donc aucune tache bloquee en D state n'est
    # recherchee. Ce detecteur complete le watchdog des blocages CPU.
    if scan_disabled_hung_task_detector() == 0:
        m.add(
            "Detecteur de tache bloquee desactive",
            "kernel.hung_task_timeout_secs = 0 signifie un delai infini : aucune tache restee en D state n'est signalee. Utiliser un delai positif adapte a la latence normale du stockage, sans activer automatiquement le panic.",
            "LOW",
            verify="sysctl kernel.hung_task_timeout_secs kernel.hung_task_check_interval_secs kernel.hung_task_panic",
        )

    # Le detecteur peut rester actif tout en devenant silencieux : ce budget est
    # decremente apres chaque signalement et 0 supprime les avertissements futurs.
    silent_hung_tasks = scan_silent_hung_task_detector()
    if silent_hung_tasks is not None:
        timeout, warnings = silent_hung_tasks
        m.add(
            "Alertes de taches bloquees epuisees",
            f"kernel.hung_task_timeout_secs = {timeout}, mais kernel.hung_task_warnings = {warnings} : le detecteur continue ses controles sans emettre aucun nouvel avertissement. Retablir un budget positif ou -1 apres avoir traite les blocages legitimes.",
            "LOW",
            verify="sysctl kernel.hung_task_timeout_secs kernel.hung_task_warnings kernel.hung_task_panic",
        )

    destructive_sysrq = scan_destructive_magic_sysrq()
    if destructive_sysrq is not None:
        value, actions = destructive_sysrq
        m.add(
            "Magic SysRq autorise des actions destructrices",
            f"kernel.sysrq = {value} autorise depuis le clavier : {', '.join(actions)}. Conserver seulement les bits de recuperation necessaires ; ce reglage ne bloque pas /proc/sysrq-trigger pour un administrateur.",
            "LOW",
            verify="sysctl kernel.sysrq; stat -c '%A %U %G %n' /proc/sysrq-trigger",
        )

    # Contrairement a une projection memoire ordinaire, un segment SysV ne
    # disparait pas forcement avec son createur. Ne signaler que les objets sans
    # attache, vieux d'au moins une heure et dont le PID createur n'existe plus.
    orphaned_shm = scan_orphaned_sysv_shared_memory()
    if orphaned_shm:
        total_bytes = sum(item["size"] for item in orphaned_shm)
        examples = ", ".join(
            f"shmid={item['shmid']} uid={item['owner_uid']} taille={item['size']}"
            for item in orphaned_shm[:3]
        )
        suffix = "" if len(orphaned_shm) <= 3 else f" (+{len(orphaned_shm) - 3} autres)"
        m.add(
            "Segments de memoire partagee SysV orphelins",
            f"{len(orphaned_shm)} segment(s) sans processus attache ni createur vivant depuis au moins une heure ({total_bytes} octets reserves) : {examples}{suffix}. Verifier les applications puis supprimer uniquement les identifiants obsoletes avec ipcrm.",
            "LOW",
            verify="cat /proc/sysvipc/shm; ipcs -m; sysctl kernel.shm_rmid_forced",
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

    # debugfs et tracefs exposent des interfaces internes du kernel. La racine
    # debugfs est volontairement root-only par défaut ; une ouverture par mode,
    # UID ou GID doit donc rester une délégation explicite et étroitement bornée.
    for fs_type, mountpoint, mode, uid, gid in scan_exposed_kernel_debug_mounts():
        m.add(
            "Interface de debug kernel accessible hors de root",
            f"{fs_type} est monte sur {mountpoint} avec les droits {mode:03o} et appartient a UID {uid}, GID {gid}. Ce pseudo-systeme expose des commandes et donnees internes du kernel ; restaurer une racine 0700 root:root ou documenter strictement le groupe delegue.",
            "MEDIUM",
            verify="findmnt -t debugfs,tracefs -o TARGET,FSTYPE,OPTIONS; stat -c '%a %A %U %G %n' /sys/kernel/debug /sys/kernel/tracing",
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

    delegated_io_uring_group = scan_io_uring_group_delegation()
    if delegated_io_uring_group is not None:
        m.add(
            "Acces io_uring delegue a un groupe",
            f"kernel.io_uring_disabled = 1 mais kernel.io_uring_group = {delegated_io_uring_group}. Les membres de ce GID peuvent encore creer des instances io_uring sans CAP_SYS_ADMIN ; verifier que cette delegation est volontaire et que le groupe reste limite.",
            "INFO",
            verify="sysctl kernel.io_uring_disabled kernel.io_uring_group; getent group $(cat /proc/sys/kernel/io_uring_group)",
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

    # La compatibilité ABI d'AppArmor peut dispenser les anciennes politiques
    # de la médiation userns. Le mode force ferme ce contournement, au risque de
    # casser un profil ancien qui ne déclare pas encore explicitement userns.
    if scan_legacy_apparmor_userns_bypass() == (1, 1, 0):
        path = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns_force"
        m.add(
            "Anciennes ABI AppArmor exemptées de la médiation userns",
            f"{path} = 0 alors que la restriction userns est active. Les politiques anciennes peuvent contourner cette médiation par compatibilité ABI ; utiliser 1 seulement après avoir actualisé et testé les profils AppArmor.",
            "LOW",
            verify="sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.apparmor_restrict_unprivileged_userns_force",
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
    # les hotes qui utilisent volontairement kexec ou kdump. Les deux compteurs
    # limitent separement les images normales et de crash sans fermer kexec.
    if scan_kexec_enabled() == 0:
        path = "/proc/sys/kernel/kexec_load_disabled"
        unlimited = scan_unlimited_kexec_loads()
        limit_detail = (
            f" Les chargements d'images {', '.join(unlimited)} sont en plus sans limite (-1) ; "
            "fixer un nombre positif adapte peut reduire l'exposition sans desactiver kexec."
            if unlimited else ""
        )
        m.add(
            "Remplacement du kernel par kexec encore autorise",
            f"{path} = 0. Le verrou kexec n'est pas active ; envisager 1 seulement si ni kexec ni kdump ne sont requis (irreversible jusqu'au redemarrage).{limit_detail}",
            "LOW",
            verify="sysctl kernel.kexec_load_disabled kernel.kexec_load_limit_reboot kernel.kexec_load_limit_panic",
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

    # La verification cryptographique peut être compilée sans être obligatoire :
    # dans ce mode permissif, le kernel documente qu'un module non signe reste
    # chargeable et ne fait que marquer le kernel comme tainted. Lockdown, le
    # verrou global, CONFIG_MODULE_SIG_FORCE ou module.sig_enforce=1 compensent.
    module_signature_policy = scan_permissive_module_signatures()
    if module_signature_policy is not None:
        support = (
            "La verification existe mais reste permissive"
            if module_signature_policy == "permissive" else
            "Ce kernel n'a pas le support de verification des signatures"
        )
        m.add(
            "Modules noyau non signes encore chargeables",
            f"{support}, tandis que le chargement dynamique et Kernel Lockdown restent ouverts. Un module sans signature valide peut donc entrer dans le kernel avec CAP_SYS_MODULE ; activer module.sig_enforce=1 au demarrage ou CONFIG_MODULE_SIG_FORCE apres avoir signe tous les modules requis.",
            "LOW",
            verify="grep '^CONFIG_MODULE_SIG' /boot/config-$(uname -r); cat /proc/cmdline; cat /proc/sys/kernel/modules_disabled; cat /sys/kernel/security/lockdown",
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


def scan_deleted_executable_mappings(proc_root="/proc"):
    """Retourne les fichiers supprimes encore mappes avec le droit d'execution."""
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
            executable = os.readlink(os.path.join(proc_dir, "exe"))
        except OSError:
            executable = None
        try:
            with open(os.path.join(proc_dir, "maps"), encoding="utf-8", errors="replace") as maps:
                targets = set()
                for line in maps:
                    fields = line.rstrip("\n").split(maxsplit=5)
                    if len(fields) < 6 or "x" not in fields[1]:
                        continue
                    target = fields[5]
                    if not target.endswith(" (deleted)") or target == executable:
                        continue
                    # Les memfd sont normalement affiches comme supprimes et sont
                    # audites separement par leur politique d'execution.
                    if target.startswith(("/memfd:", "/SYSV")):
                        continue
                    targets.add(target)
        except OSError:
            continue
        if not targets:
            continue
        name = "unknown"
        try:
            with open(os.path.join(proc_dir, "comm"), encoding="utf-8", errors="replace") as comm:
                name = comm.read().strip() or name
        except OSError:
            pass
        found.extend(
            {"pid": int(pid), "name": name, "target": target}
            for target in sorted(targets)
        )
    return sorted(found, key=lambda item: (item["pid"], item["target"]))


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

        # /proc/PID/exe ne montre que le programme principal. Une bibliotheque
        # supprimee peut pourtant rester executable dans les mappings du processus.
        deleted_mappings = scan_deleted_executable_mappings()
        routine_updates = []
        for mapping in deleted_mappings:
            severity = classify_deleted_executable(mapping["target"])
            if severity == "LOW":
                routine_updates.append(mapping)
                continue
            m.add(
                "Code supprime encore charge depuis un dossier temporaire",
                f"PID {mapping['pid']} ({mapping['name']}) execute encore {mapping['target']}. Capturer et identifier le mapping rapidement.",
                "HIGH",
                verify=f"sudo grep -F ' (deleted)' /proc/{mapping['pid']}/maps; sudo ps -fp {mapping['pid']}",
            )
        if routine_updates:
            processes = sorted({
                (mapping["pid"], mapping["name"])
                for mapping in routine_updates
            })
            preview = ", ".join(
                f"{pid} ({name})" for pid, name in processes[:8]
            )
            if len(processes) > 8:
                preview += f", +{len(processes) - 8} autres"
            m.add(
                "Services utilisant encore des bibliotheques remplacees",
                f"{len(routine_updates)} mapping(s) executable(s) supprime(s) dans {len(processes)} processus : {preview}. Frequent apres une mise a jour ; redemarrer les services apres validation.",
                "LOW",
                verify="sudo grep -l -F ' (deleted)' /proc/[0-9]*/maps 2>/dev/null",
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
