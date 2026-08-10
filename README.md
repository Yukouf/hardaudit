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

Exporter un rapport ou obtenir du JSON :

```bash
sudo hardaudit -o rapport.txt
sudo hardaudit --json
```

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
| Réseau | 12 | CIS 3.x | Écoutes sur toutes les interfaces, sans confondre écoute locale et exposition Internet |
| Firewall | 12 | CIS 3.5 | UFW/nftables/iptables et politique entrante effective deny/drop |
| Mises à jour | 10 | CIS 1.8 / ANSSI R3 | Paquets à mettre à jour, unattended-upgrades |
| Kernel | 14 | CIS 1.6 / ANSSI R14 | ASLR, ptrace, syncookies, protections hardlink/symlink/FIFO/fichiers de `/tmp` |
| Services | 10 | CIS 2.x | Services obsolètes, cron jobs, binaires supprimés encore actifs |
| Filesystem | 10 | CIS 1.1 / ANSSI R28 | /tmp executable, world-writable, sticky bit, shadow |
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

# Processus utilisant encore un ancien binaire après mise à jour
sudo ls -l /proc/PID/exe
sudo ps -fp PID

# Protections contre les fichiers et liens piégés dans les dossiers partagés
sysctl fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular
```

> **Important :** le score est un indicateur de triage, pas une certification CIS/ANSSI. Un finding prouve une configuration observée, pas automatiquement une compromission. Le contexte de la machine reste indispensable.

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
  ⚠ [MEDIUM  ] Core dumps SUID actifs
     /proc/sys/fs/suid_dumpable = 2 (attendu: 0)

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

## 🛣️ Roadmap

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
