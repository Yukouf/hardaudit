# HardAudit — Audit de sécurité de VM Linux

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stdlib Only](https://img.shields.io/badge/Deps-Zero-green)](hardaudit.py)
[![CIS](https://img.shields.io/badge/Based%20on-CIS%20Benchmarks-005571)](https://www.cisecurity.org/benchmark/debian_linux)
[![Tests](https://img.shields.io/badge/Tests-261%20OK-2EA043)](test_hardaudit.py)

HardAudit audite la sécurité d'une VM Linux en une commande : il vérifie
9 domaines (accès, SSH, réseau, pare-feu, mises à jour, noyau, services,
système de fichiers, logs), produit une **note sur 100**, un grade, et des
constats exploitables référencés CIS / ANSSI.

Conçu pour : auditeurs, équipes SOC, administrateurs — et pour alimenter des
**analyses de données** (sortie JSON structurée, agrégation multi-machines).

## Caractéristiques

- **Zéro dépendance** : un seul fichier Python, bibliothèque standard (Python 3.8+), pas de `pip install`, pas de Docker
- **Note sur 100** avec grade (A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F)
- **Sorties** : console, TXT, **JSON documenté** (avec références CIS/ANSSI par constat)
- **Exploitable en automatisation** : code de sortie non nul si note < 80 (intégration CI/CD)
- **261 tests** unitaires, sans dépendance externe
- **Non intrusif** : lit l'état du système sans le modifier
- Références **CIS Benchmarks** et **recommandations ANSSI** par module

## Installation — 1 commande

Sur n'importe quel serveur Linux (sans git) :

```bash
curl -fsSL https://raw.githubusercontent.com/Yukouf/hardaudit/main/install.sh | sudo bash
```

L'installateur : installe Python 3 si nécessaire, déploie l'outil + la
surveillance hebdomadaire (audit automatique le lundi à 7h, alerte si la note
baisse), et lance le premier audit.

Options : `--no-cron` (sans surveillance hebdo), `--no-audit`, `--dir=/chemin`.

## Démarrage rapide

```bash
sudo hardaudit                 # audit complet (console)
sudo hardaudit --json          # sortie JSON structurée
sudo hardaudit -o rapport.txt  # export TXT
```

Exemple de sortie :

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

SCORE FINAL : 41/100 — 41% — GRADE D
```

## Architecture

![Architecture](assets/architecture.svg)

HardAudit lit la configuration et l'état du système sans les modifier. Ses
neuf modules produisent des constats pondérés, regroupés en un score sur 100,
un grade et des sorties console, TXT ou JSON. Un score inférieur à 80
provoque un code de sortie non nul pour l'automatisation.

Adapter le score au contexte métier sans masquer les preuves :

```bash
sudo hardaudit --allow-port 3306 --allow-port 10050
```

Les ports déclarés restent visibles en `INFO` dans le terminal, le TXT et le
JSON, mais ne réduisent plus le score. Cette option ne doit être utilisée
qu'après identification du processus et validation que l'écoute est
intentionnelle.

## Les 9 modules d'audit

| Module | Points | Référence | Ce qu'il vérifie |
|---|---|---|---|
| Utilisateurs | 12 | CIS 5.x | Root accessible, UID 0 non-root, sudo sans mot de passe, umask |
| SSH | 12 | CIS 5.2 / ANSSI R5 | PermitRootLogin, PasswordAuthentication, X11Forwarding, port |
| Réseau | 12 | CIS 3.x | Écoutes wildcard, anti-spoofing (`rp_filter`), routes IPv4 imposées par la source, politique/chiffrement IPsec, ARP, en-têtes de routage IPv6, SRv6, DAD, redirects ICMP, broadcasts dirigés, annonces IPv6, PMTU, protections TCP |
| Firewall | 12 | CIS 3.5 | UFW/nftables/iptables et politique entrante effective deny/drop |
| Mises à jour | 10 | CIS 1.8 / ANSSI R3 | Paquets à mettre à jour, unattended-upgrades |
| Kernel | 14 | CIS 1.6 / ANSSI R14 | ASLR, mitigations CPU, slab isolation, BPF, io_uring, userfaultfd, core dumps, verrous kexec/modules, LSM, protections mémoire |
| Services | 10 | CIS 2.x | Services obsolètes, cron jobs, binaires et bibliothèques supprimés encore exécutables en mémoire |
| Filesystem | 10 | CIS 1.1 / ANSSI R28 | `/tmp` exécutable, cloisonnement `nodev,nosuid,noexec` de `/dev/shm`, world-writable, sticky bit, shadow, visibilité inter-utilisateurs de `/proc` |
| Logs | 8 | CIS 4.x | auditd, rsyslog, logrotate |

## Scoring

| Score | Grade | Interprétation |
|---|---|---|
| ≥ 90 | A | Durcissement solide |
| ≥ 75 | B | Bon niveau, points résiduels |
| ≥ 60 | C | Correctif nécessaire |
| ≥ 40 | D | Durcissement insuffisant |
| < 40 | F | Machine exposée |

### Sortie JSON (pour analyses de données)

La sortie `--json` est pensée pour l'exploitation des données (analystes, tableaux de bord, historique) :

```json
{
  "host": "srv-prod-01",
  "date": "2026-09-01T13:26:25",
  "score": 74,
  "max": 100,
  "grade": "C",
  "summary": { "INFO": 1, "LOW": 32, "MEDIUM": 8, "HIGH": 2, "CRITICAL": 0, "total": 43 },
  "modules": [
    {
      "name": "SSH", "ref": "CIS 5.2 / ANSSI R5", "score": 12, "max": 12,
      "findings": [
        { "title": "PermitRootLogin = yes", "severity": "HIGH",
          "ref": "CIS 5.2 / ANSSI R5", "detail": "…", "verify": "…" }
      ]
    }
  ]
}
```

- **Exemple réel** : [`examples/hardaudit_sample.json`](examples/hardaudit_sample.json)
- **`ref`** : référence CIS / ANSSI par module et par constat → jointures avec les référentiels
- **`summary`** : compteurs par sévérité au niveau racine, sans parsing des constats
- **Suivi temporel** : la surveillance hebdo écrit `historique.csv` (`date,score,hostname`) → séries temporelles

### Collecte multi-machines

[`hardaudit_collect.py`](hardaudit_collect.py) exécute l'audit sur un parc
(machine locale + hôtes distants via SSH) et agrège :

```bash
sudo python3 hardaudit_collect.py --local --hosts admin@vps1 admin@vps2
# → hardaudit_data/dataset_AAAAMMJJ.json (audits bruts complets)
# → hardaudit_data/synthese_AAAAMMJJ.csv  (hôte × score × sévérités, prêt pandas/Excel)
```

## Vérification des résultats

Les commandes permettant de reproduire et confirmer chaque constat sont
documentées dans [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Structure

```
hardaudit/
├── hardaudit.py            # l'outil — un seul fichier, zéro dépendance
├── hardaudit_collect.py    # collecte multi-machines (dataset JSON + CSV)
├── hardaudit_watch.sh      # surveillance hebdomadaire (cron)
├── install.sh              # installateur 1 commande
├── test_hardaudit.py       # 261 tests, sans dépendance externe
├── examples/               # exemples de sorties (JSON réel)
├── docs/                   # documentation technique (vérifications)
├── assets/                 # schémas
├── LICENSE                 # MIT
└── README.md
```

## Comparaison avec les alternatives

| Outil | Dépendances | Poids | Style | Export |
|---|---|---|---|---|
| **HardAudit** | **0** | **~166 Ko** | **Score/100 + constats lisibles** | **Console / TXT / JSON** |
| Lynis | Shell + 300 fichiers | 3 Mo | Logs verbeux | HTML/TXT |
| OpenSCAP | XML + XSLT + 50 paquets | 50 Mo+ | XML dense | HTML |
| CIS-CAT | Java | 200 Mo+ | Rapports PDF | PDF |

HardAudit vise un **premier avis rapide et reproductible** sur une VM. Pour
un audit de certification complet, Lynis ou OpenSCAP restent les références.

Comparaison documentée avec Lynis, OpenSCAP, CIS-CAT, Tiger, osquery et
Wazuh SCA : [`COMPARAISON_REFERENCES.md`](COMPARAISON_REFERENCES.md).
HardAudit reprend des concepts génériques (profils, statuts par règle,
preuves, suivi de conformité) sans copier de code GPL ni de contenu
propriétaire CIS.

## Roadmap

- [x] 9 modules d'audit · scoring /100 · grades A-F
- [x] Sorties console, TXT, JSON (schéma documenté, références CIS/ANSSI)
- [x] Zéro dépendance · 261 tests · collecte multi-machines
- [ ] Export HTML avec graphiques
- [ ] Module Docker security
- [ ] Auto-fix (`--fix`) pour les corrections simples

## Licence

[MIT](LICENSE) — libre d'utilisation, de modification et d'intégration, y
compris en entreprise.

---

Maintenu par [Youssef Guerniou](https://github.com/Yukouf) — cybersécurité,
automatisation défensive et sécurité des systèmes.
