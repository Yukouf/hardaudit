# ☠️ HardAudit — Audit de sécu Linux qui fait mal

```
██╗  ██╗ █████╗ ██████╗ ██████╗  █████╗ ██╗   ██╗██████╗ ██╗████████╗
██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
███████║███████║██████╔╝██║  ██║███████║██║   ██║██║  ██║██║   ██║
██╔══██║██╔══██║██╔══██╗██║  ██║██╔══██║██║   ██║██║  ██║██║   ██║
██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
```

> **Un script. 9 modules. Un score sur 100. Des actions concrètes. Zéro bullshit.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stdlib Only](https://img.shields.io/badge/Deps-Zero-green)](hardaudit.py)
[![CIS](https://img.shields.io/badge/Based%20on-CIS%20Benchmarks-005571)](https://www.cisecurity.org/benchmark/debian_linux)

---

## 🤔 Le problème

T'as 50 VMs Linux à auditer. T'as pas le temps de passer 2h sur chaque. Les outils existants (Lynis, OpenSCAP) sont lourds, verbeux, et te crachent 500 lignes que personne ne lit.

Toi, tu veux :
- Un **score** rapide pour savoir si c'est la cata ou pas
- Les **actions prioritaires** pour corriger
- Un **rapport** que tu peux filer au client
- Quelque chose qui tourne **sans rien installer**

---

## 💡 La solution

**HardAudit** — un fichier Python, zéro dépendance. Tu le balances sur n'importe quelle VM Linux et il te dit ce qui pue.

```bash
sudo python3 hardaudit.py
```

```
╔══════════════════════════════════════════╗
║  SCORE FINAL : 41/100 — 41% — GRADE D  ║
╚══════════════════════════════════════════╝

  █████████░ Reseau & Ports             11/12 ✓
  ██████████ Firewall                   12/12 ✓
  █████░░░░░ Mises a jour               5/10  ⚠1
  ░░░░░░░░░░ SSH                         0/12  ⚠3
  ░░░░░░░░░░ Systeme de fichiers         0/10  ⚠2

  ACTIONS PRIORITAIRES :
  ☠ /etc/shadow lisible
  ▲ PermitRootLogin = yes
  ▲ Aucun firewall actif
```

---

## ⚡ Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Yukouf/hardaudit/main/hardaudit.py \
  | sudo tee /usr/local/bin/hardaudit >/dev/null \
  && sudo chmod +x /usr/local/bin/hardaudit
```

Puis lance l'audit depuis n'importe quel dossier :

```bash
sudo hardaudit
```

## 🏗️ Architecture

![Architecture réelle de HardAudit](assets/architecture.svg)

HardAudit lit la configuration et l’état du système sans les modifier. Ses neuf modules produisent des constats pondérés, regroupés en un score sur 100, un grade et des sorties console, TXT ou JSON. Un score inférieur à 80 provoque un code de sortie non nul pour l’automatisation.

Exporter un rapport ou obtenir du JSON :

```bash
sudo hardaudit -o rapport.txt
sudo hardaudit --json
```

Adapter le score au contexte métier sans masquer les preuves :

```bash
sudo hardaudit --allow-port 3306 --allow-port 10050
```

Les ports déclarés restent visibles en `INFO` dans le terminal, le TXT et le JSON, mais ne réduisent plus le score. N'utilise cette option qu'après avoir identifié le processus et validé que l'écoute est intentionnelle.

Désinstaller :

```bash
sudo rm /usr/local/bin/hardaudit
```

Pas de `pip install`, de virtualenv ou de Docker : **Python 3.8+ suffit.**

---

## 🧠 Les 9 modules d'audit

| Module | Points | Référence | Ce qu'il vérifie |
|---|---|---|---|
| Utilisateurs | 12 | CIS 5.x | Root accessible, UID 0 non-root, sudo sans mdp, umask |
| SSH | 12 | CIS 5.2 / ANSSI R5 | PermitRootLogin, PasswordAuth, X11Forwarding, port |
| Réseau | 12 | CIS 3.x | Écoutes wildcard, validation anti-spoofing (`rp_filter`), acceptation et émission effectives des redirects ICMP IPv4 par interface |
| Firewall | 12 | CIS 3.5 | UFW/nftables/iptables et politique entrante effective deny/drop |
| Mises à jour | 10 | CIS 1.8 / ANSSI R3 | Paquets à mettre à jour, unattended-upgrades |
| Kernel | 14 | CIS 1.6 / ANSSI R14 | ASLR, ptrace, perf_events, syncookies, BPF non privilégié et durcissement du JIT BPF, io_uring globalement ouvert et sans médiation AppArmor sur les kernels compatibles, userfaultfd non restreint, memfd exécutables par défaut, namespaces utilisateur sans médiation AppArmor, page mémoire nulle, autoload TTY et injection TIOCSTI historique, verrous kexec/modules/Lockdown, masquage des pointeurs kernel (modes renforcés acceptés), protections hardlink/symlink/FIFO/fichiers de `/tmp` |
| Services | 10 | CIS 2.x | Services obsolètes, cron jobs, binaires supprimés encore actifs |
| Filesystem | 10 | CIS 1.1 / ANSSI R28 | /tmp executable, world-writable, sticky bit, shadow, visibilité inter-utilisateurs de `/proc` |
| Logs | 8 | CIS 4.x | auditd, rsyslog, logrotate |

---

## 📊 Scoring

```
Score    Grade   Interprétation
─────────────────────────────────
90-100   A       Excellent — machine bien sécurisée
75-89    B       Bon — quelques améliorations mineures
60-74    C       Plusieurs contrôles à examiner
40-59    D       Durcissement nettement incomplet
0-39     F       Nombreux contrôles non satisfaits — analyse manuelle indispensable
```

Chaque finding a une sévérité :

| Sévérité | Pénalité | Icône |
|---|---|---|
| LOW | -1 | `i` |
| MEDIUM | -3 | `⚠` |
| HIGH | -5 | `▲` |
| CRITICAL | -10 | `☠` |

---

## 🔎 Vérifier les résultats

Chaque résultat sensible affiche désormais une ligne **`Verifier :`** avec la commande système indépendante qui permet de contrôler le fait observé. HardAudit ne doit donc pas être cru sur parole.

Exemples :

```bash
# Permissions et propriétaire réels de /etc/shadow
sudo stat -c '%a %U %G %n' /etc/shadow

# Configuration SSH réellement appliquée (valeurs par défaut + Include)
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|x11forwarding|maxauthtries|clientaliveinterval) '

# Programme associé à un port
sudo ss -ltnp

# Validation de l'adresse source IPv4 (0 = absente, 1 = stricte, 2 = souple)
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter
grep -H . /proc/sys/net/ipv4/conf/*/rp_filter

# Redirects ICMP IPv4 : la règle effective dépend aussi du mode hôte/routeur de chaque interface
grep -H . /proc/sys/net/ipv4/conf/{all,default,*/}{accept_redirects,forwarding} 2>/dev/null

# Émission de redirects : sur une interface routeur, `all=1` OU la valeur locale suffit
grep -H . /proc/sys/net/ipv4/conf/{all,default,*/}{send_redirects,forwarding} 2>/dev/null

# Processus utilisant encore un ancien binaire après mise à jour
sudo ls -l /proc/PID/exe
sudo ps -fp PID

# Protections contre les fichiers et liens piégés dans les dossiers partagés
sysctl fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular

# Visibilité des processus entre comptes locaux (hidepid=0 par défaut, 1/2/4 restreints)
findmnt /proc -o TARGET,FSTYPE,OPTIONS
runuser -u nobody -- test -r /proc/1/status

# Core dumps privilégiés : 0 = désactivés ; 1 = dangereux ; 2 = sûr seulement avec pipe ou chemin absolu
sysctl fs.suid_dumpable kernel.core_pattern

# Masquage des pointeurs kernel (0 = exposés, 1 = restreints, 2 = masqués même pour root)
sysctl kernel.kptr_restrict

# Accès au syscall BPF par les utilisateurs non privilégiés (0 = autorisé, 1/2 = bloqué)
sysctl kernel.unprivileged_bpf_disabled

# Durcissement anti-JIT-spraying de BPF (0 = absent, 1 = non privilégiés, 2 = tous)
sysctl net.core.bpf_jit_harden

# Profilage perf (valeur minimale 2 : aucun événement kernel sans privilège)
sysctl kernel.perf_event_paranoid

# Création d'instances io_uring (0 = tous, 1 = groupe dédié, 2 = désactivée)
sysctl kernel.io_uring_disabled

# Sur les kernels compatibles : médiation AppArmor de io_uring pour les comptes non privilégiés
[ ! -e /proc/sys/kernel/apparmor_restrict_unprivileged_io_uring ] || \
  sysctl kernel.apparmor_restrict_unprivileged_io_uring

# Interception userfaultfd des fautes kernel (0 = CAP_SYS_PTRACE requis, 1 = non restreint)
sysctl vm.unprivileged_userfaultfd
[ ! -e /dev/userfaultfd ] || stat -c '%A %U %G %n' /dev/userfaultfd

# Exécution depuis un fichier anonyme memfd (0 = implicite, 1 = explicite, 2 = refusée)
sysctl vm.memfd_noexec

# Sur les kernels Ubuntu compatibles : userns peut rester disponible tout en étant médié par AppArmor
sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns
runuser -u nobody -- unshare --user --map-root-user true

# Plancher des projections mémoire (0 = page nulle accessible, 65536 = valeur courante)
sysctl vm.mmap_min_addr

# Autoload des disciplines TTY (0 = réservé à CAP_SYS_MODULE, 1 = non privilégié)
sysctl dev.tty.ldisc_autoload

# Injection de frappes TIOCSTI (0 = réservé à CAP_SYS_ADMIN, 1 = comportement historique)
sysctl dev.tty.legacy_tiocsti

# Verrou kexec (1 = aucun nouveau kernel chargeable, irréversible jusqu'au redémarrage)
sysctl kernel.kexec_load_disabled

# Verrou des modules (1 = ni chargement ni retrait, irréversible jusqu'au redémarrage)
sysctl kernel.modules_disabled
lsmod

# Kernel Lockdown ([none] = inactif ; integrity/confidentiality = actifs)
cat /sys/kernel/security/lockdown
cat /proc/cmdline
```

> **Important :** le score est un indicateur de triage, pas une certification CIS/ANSSI. Un finding prouve une configuration observée, pas automatiquement une compromission. Le contexte de la machine reste indispensable.

> **Faux positif kexec :** conserver `kernel.kexec_load_disabled=0` est légitime sur un hôte utilisant `kexec` ou `kdump`. Ne jamais passer ce verrou à `1` avant d'avoir vérifié ces usages : le kernel documente qu'il ne peut plus être annulé avant un redémarrage.

> **Faux positif modules :** conserver `kernel.modules_disabled=0` est normal sur une machine qui utilise le hotplug, DKMS ou charge encore des pilotes après le démarrage. La valeur `1` vise surtout les appliances stables ; elle bloque aussi le retrait des modules et ne peut plus être annulée avant un redémarrage.

> **Faux positif Lockdown :** le mode `none` est courant sur une VM sans Secure Boot et n'indique pas une compromission. `integrity` ou `confidentiality` est surtout pertinent pour une chaîne de démarrage maîtrisée ; tester auparavant les modules, kexec et outils de diagnostic qui peuvent être bloqués.

> **Faux positif userns :** navigateurs, sandbox et outils de conteneurs peuvent dépendre des namespaces utilisateur. HardAudit ne signale ce point que si le kernel expose la médiation AppArmor dédiée, que `unprivileged_userns_clone=1` et que cette médiation vaut `0` ; tester les profils applicatifs avant de l'activer.

> **Faux positif JIT BPF :** le mode `2` durcit aussi les programmes chargés par des processus privilégiés mais peut coûter en performances. Le mode `1` peut être un compromis acceptable, surtout si le BPF non privilégié est déjà bloqué ; le finding reste donc `LOW` et doit être arbitré selon les usages réseau et observabilité.

> **Faux positif io_uring :** navigateurs, bases de données et runtimes peuvent dépendre de io_uring. Sur les kernels qui exposent `apparmor_restrict_unprivileged_io_uring`, HardAudit indique si cette médiation de repli est inactive sans ajouter une seconde pénalité ; tester les profils AppArmor avant activation.

> **Faux positif core dumps SUID :** `fs.suid_dumpable=2` n'est pas automatiquement dangereux. Le kernel l'autorise avec un `core_pattern` dirigé vers un handler (`|...`) ou un chemin absolu ; HardAudit vérifie désormais les deux valeurs ensemble. Le mode `1`, lui, reste réservé au débogage car il permet aux utilisateurs ordinaires d'examiner la mémoire de processus privilégiés.

> **Faux positif rp_filter :** le mode strict `1` peut casser le routage asymétrique ou certains montages multi-interface. Le mode souple `2` vérifie que la source est joignable par une interface et constitue alors le compromis documenté par le kernel ; HardAudit accepte les deux et tient compte du maximum entre `conf/all` et chaque interface.

> **Faux positif redirects ICMP :** un routeur administré peut utiliser volontairement les redirects. HardAudit calcule la règle documentée par le kernel par interface : en mode hôte, `all=1` **ou** `interface=1` suffit ; avec le forwarding actif, les deux doivent valoir `1`. Le finding prouve l'acceptation locale, pas une attaque en cours.

> **Faux positif émission de redirects :** HardAudit ne signale que les interfaces qui routent réellement et dont `send_redirects` est effectif (`all=1` **ou** `interface=1`). Un routeur administré peut en avoir besoin ; le finding `LOW` indique une capacité active, pas un détournement en cours.

> **Faux positif memfd :** des runtimes, navigateurs ou moteurs JIT peuvent légitimement exécuter du code depuis un memfd. Le mode `1` conserve cette possibilité avec `MFD_EXEC` explicite ; le mode `2` la bloque et doit être testé avec les applications avant déploiement.

> **Faux positif hidepid :** ce durcissement apporte peu sur une machine réellement mono-utilisateur et peut gêner certains agents de supervision. Sur un serveur partagé, `hidepid=1` protège déjà les fichiers sensibles des processus ; `hidepid=2` masque aussi leurs répertoires. Tester le monitoring avant de modifier le montage de `/proc`.

> **Faux positif TIOCSTI :** certains logiciels historiques de terminal peuvent encore dépendre de cette injection. La valeur `0` convient à la plupart des systèmes modernes, mais les processus ayant `CAP_SYS_ADMIN` restent autorisés ; valider les outils d'accessibilité et de terminal avant déploiement global.

---

## 🎬 Ce que ça donne en vrai

```bash
$ sudo python3 hardaudit.py
```

```
  [2/12] Utilisateurs & Authentification  CIS 5.x
  ▲ [HIGH    ] Root login actif
     Shell root = /bin/bash. Désactiver le login root direct.
  ▲ [HIGH    ] Sudo sans mot de passe
     NOPASSWD:ALL actif — toute commande sans authentification.

  [0/12] SSH  CIS 5.2 / ANSSI R5
  ▲ [HIGH    ] PermitRootLogin = yes
     Désactiver PermitRootLogin.
  ⚠ [MEDIUM  ] PasswordAuthentication non défini
     Utiliser uniquement des clés SSH.

  [12/12] Firewall  CIS 3.5
  ✓ Aucune anomalie détectée

  [7/14] Kernel & Protections  CIS 1.6 / ANSSI R14
  ⚠ [MEDIUM  ] IP forwarding actif
     /proc/sys/net/ipv4/ip_forward = 1 (attendu: 0)

  [0/10] Système de fichiers  CIS 1.1 / ANSSI R28
  ☠ [CRITICAL] /etc/shadow lisible
     Permissions trop larges sur /etc/shadow.
```

---

## 📁 Structure

```
hardaudit/
├── hardaudit.py      # Le script — tout tient dans un seul fichier
├── test_hardaudit.py # Tests sans dépendance externe
├── assets/architecture.svg # Schéma d’architecture vectoriel
├── LICENSE           # MIT
└── README.md         # Ce fichier
```

---

## 🔧 Comparaison avec les alternatives

| Outil | Dépendances | Poids | Style | Export |
|---|---|---|---|---|
| **HardAudit** | **0** | **25 Ko** | **Score/100 + couleurs** | **TXT** |
| Lynis | Shell + 300 fichiers | 3 Mo | Logs verbeux | HTML/TXT |
| OpenSCAP | XML + XSLT + 50 paquets | 50 Mo+ | XML imbuvable | HTML |
| CIS-CAT | Java | 200 Mo+ | Rapports PDF | PDF |

HardAudit, c'est l'outil que tu balances en 2 secondes sur une VM pour avoir un premier avis. Pas l'audit de certification ANSSI — pour ça, Lynis ou OpenSCAP.

---

## 🔬 Comparaison avec les références

La comparaison documentée avec Lynis, OpenSCAP, CIS-CAT, Tiger, osquery et Wazuh SCA est disponible dans [`COMPARAISON_REFERENCES.md`](COMPARAISON_REFERENCES.md). HardAudit reprend des **concepts génériques** — profils, statuts par règle, preuves et suivi de conformité — mais ne copie ni code GPL ni contenu propriétaire CIS.

---

## 🗺️ Roadmap

- [x] 9 modules d'audit
- [x] Scoring sur 100 + grades A-F
- [x] Couleurs ANSI + barres de progression
- [x] Export TXT
- [x] Zéro dépendance
- [x] Détection des processus dont le binaire a été supprimé
- [ ] Export HTML avec graphiques
- [ ] Mode non-interactif pour CI/CD (--json déjà fait)
- [ ] Module Docker security
- [ ] Auto-fix (--fix) pour les corrections simples

---

## ⚖️ Licence

MIT — Utilise, modifie, intègre à tes outils. Si ça t'a sauvé une VM, crédite l'auteur.

---

*Built with ☠️ by [Youssef Guerniou](https://github.com/Yukouf) — parce que `/etc/shadow` en 644, ça pique.*
