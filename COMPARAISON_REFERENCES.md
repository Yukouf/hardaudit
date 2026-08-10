# HardAudit vs références établies d'audit/hardening Linux

Analyse comparative (état 2026) et recommandations. Outils étudiés : **Lynis, OpenSCAP, CIS-CAT Lite/Pro, Tiger, osquery, Wazuh SCA**.

---

## 1. Fiches par outil

### HardAudit (projet local)
- **Nature** : script Python unique (~700 lignes, stdlib uniquement), sans dépendance et exécutable sans installation permanente.
- **Architecture** : une classe `Module` (nom, poids/points, référence) et une classe `Finding` (titre, détail, sévérité, commande `verify`). 9 modules : Utilisateurs, SSH, Réseau, Firewall, Mises à jour, Kernel, Services, Filesystem, Logs. `main()` assemble les modules, calcule un score total /100 + grade A–F, exporte TXT et JSON.
- **Contrôles** : ~40 checks ciblés, chacun référencé explicitement (CIS 1.1–5.x, ANSSI R3/R5/R14/R28).
- **Preuves** : chaque finding porte une commande `Verifier :` indépendante (`stat`, `sshd -T`, `ss -ltnp`, `ls -l /proc/PID/exe`) — philosophie « ne pas croire sur parole ».
- **Anti-faux-positifs** : heuristiques réelles — `sshd -T` (config effective incl. Include + défauts), distinction écoute locale vs publique, `getpwall` pour ne pas confondre shell root et login root, politique firewall sur le backend réellement actif, classification sévérité des mises à jour, processus à binaire supprimé.
- **Tests** : 20 tests `unittest` avec `mock`, principalement des régressions anti-faux-positifs.
- **Format** : TXT (rapport) + JSON (`--json`), stderr pour logs. Sortie couleur ANSI. Échec non-nul attendu si `--quiet`… (pas de code retour de sortie différencié en fait).
- **Remédiation** : conseils textuels par finding ; pas d'auto-fix (`--fix` en roadmap).
- **Plugins/CI** : aucun plugin ; CI pas intégré mais `--json` prévu pour ça. CLI simple adaptée à un pipeline.
- **Licence** : MIT (fichier LICENSE, Youssef Guerniou, 2026).
- **Score** : dépend de l'hôte et du contexte déclaré — triage, pas certification.

### Lynis
- **Nature** : solution communautaire + entreprise (CISOfy). Le CLI est open source ; l'audit et le support sont payants (Lynis Enterprise).
- **Architecture** : interpréteur shell + +300 fichiers auxiliaires (profils `.prf`, tests dans `include/tests_*`), arborescence `Lynis/`. Il s'auto-localise, détecte l'OS et exécute des dizaines d'ensembles de tests.
- **Contrôles** : 300+ tests répartis par catégorie (booting, kernel, memory, tools, file permissions, hardening index). Produit un *Hardening Index* (/100) et un *Hardening Index of this system* avec suggestions.
- **Preuves** : log textuel très verbeux (`/var/log/lynis.log`), section de suggestions et de « *weak* » à corriger. Chaque test donne des références et commandes de correctif.
- **Profilage** : profils utilisateur `.prf` pour ajuster/limiter les tests (`--profile`).
- **Remédiation** : suggestions dans le rapport final ; pas de remédiation automatique.
- **Plugins** : plugins (shell, dans `include/plugins`) et on peut écrire des tests custom.
- **CI** : mode non-interactif ; la version communautaire produit notamment un log et un fichier de rapport machine-readable, tandis que les rapports centralisés enrichis relèvent de l'offre Enterprise.
- **Licence** : GPLv3 (code communautaire). Documentation et fonctionnalités entreprise propriétaires.
- **Forces** : très complet, mature, portabilité (pas de compilateur), hardening index plébiscité, profils.
- **Faiblesses** : lent, très verbeux, difficile à embedder, dépendances système (shell, config regex), index non conforme à un benchmark précis (pas CIS natif), entreprise = payant pour l'audit complet.
- **URL** : https://cisofy.com/lynis/ ; source https://github.com/CISOfy/lynis (GPLv3, actif).
- **Réutilisable légalement (GPL)** : concepts de *hardening index*, de profils `.prf`, et le « mode non-interactif + exit code ».

### OpenSCAP
- **Nature** : framework NIST/USABLE, composé de `openscap-scanner`, `scap-workbench`, `SSG` (SCAP Security Guide).
- **Architecture** : moteur C + librairie ; consommation de **content SCAP** (XCCDF/OVAL/DataStream) XML. Basé sur standards NIST (SCAP 1.3). `oscap` CLI + bibliothèque.
- **Contrôles** : milliers de règles couvertes par les **profils du SSG** (CIS, STIG, PCI-DSS, ANSSI… selon disitribution) ; ex : profils CIS Debian, RHEL, Fedora.
- **Preuves** : rapport XML/HTML détaillé, avec résultats de règles individuelles, OVAL (vérifications). `oscap xccdf eval --profile ... --results ... --report ...`.
- **Profilage** : profils XCCDF natifs (sélection de rulesets), variables de paramétrage, tailoring files.
- **Remédiation** : `oscap xccdf eval --remediate` (auto-remediation) ou guide de remédiation généré (`--generate fix`). Puissant mais intrusif.
- **Plugins** : pas de plugins « script » ; extensible par content SCAP personnalisé (batch OVAL personnalisés).
- **CI** : excellent — CLI non-interactif parfait pour CI/CD, sorties `--results-arf`, `--report` (HTML), exit code (0 = OK).
- **Licence** : OpenSCAP sous LGPL-2.1 ; ComplianceAsCode/content sous BSD-3-Clause. Les contenus tiers peuvent avoir leurs propres restrictions.
- **Forces** : standards interopérables (SCAP/XCCDF/OVAL), profils benchmark officiels (CIS/STIG), remédiation automatique, rapports certifiables, portée serveur massivement éprouvée.
- **Faiblesses** : très lourd (dépendances, paquets, content), XML verbeux et difficile, appétit en mémoire/CPU, overhead d'installation, courbe d'apprentissage raide, pas d'exécution de scans sur machine sans installation.
- **URL** : https://www.open-scap.org/ ; https://github.com/OpenSCAP/openscap ; https://github.com/ComplianceAsCode/content
- **Réutilisable** : le **modèle profils/règles** (ruleset + paramètre + profil) et le schéma des **résultats par règle avec niveau de conformité** ; l'usage du XML standardisé interopérable. Attention : réutiliser du *content* CIS est sous licence CIS.

### CIS-CAT Lite / Pro
- **Nature** : outils propriétaires du Center for Internet Security (CIS). **Lite** = gratuit mais limité ; **Pro/Assessor** = payant.
- **Architecture** : Java ; exécute les **CIS Benchmarks** pour cibles multiples par l'API CIS-CAT. Consomme les benchmarks officiels CIS.
- **Contrôles** : conformité directe aux benchmarks CIS (pas un index custom) : Debian, Ubuntu, RHEL, etc. Règles titrées/niveaux 1/2, sections, remédiation officielle.
- **Preuves** : rapports riches : XML, HTML, PDF, XLSX, avec détails de chaque rule (statut Pass/Fail/Error/Not-Applicable, section, niveau), screenshotting optionnel.
- **Profilage** : profils par niveau (Level 1, Level 2), par benchmark.
- **Remédiation** : guidance de remédiation intégrée par règle, sans auto-fix (CIS ne fait pas de remédiation automatique par design commercial ; Pro offre des « remediation scripts » partiels).
- **Plugins** : non ; écosystème fermé.
- **CI** : exécution headless possible, sorties machine-readable (XML/JSON) ; intégration API.
- **Licence** : propriétaire. Lite : gratuit (réarmement), pas de redistribution. Pro : licences commerciales. **Les benchmarks CIS eux-mêmes sont sous licence d'usage restreinte (CIS member/accessed), PAS librement redistribuables.**
- **Forces** : référence de fait du conformisme CIS, rapports de qualité client, règles avec impact réel et remédiation exacte, niveaux simples.
- **Faiblesses** : fermé, poids Java (200 Mo+), payant pour l'usage professionnel, pas d'extension, licences restrictives limitant la réutilisation.
- **URL** : https://www.cisecurity.org/cybersecurity-tools/cis-cat/cis-cat-pro ; Lite : https://workbench.cisecurity.org
- **Réutilisable légalement** : **les concepts de « niveaux » (Level 1/2) et la structure règle/section/statut** ne sont pas protégeables ; la **liste exacte des règles CIS ne doit pas être reproduite** sans licence. HardAudit cite « CIS 5.2 » mais réécrit ses propres checks — à garder like that.

### Tiger
- **Nature** : outil historique (Unix) d'audit de sécurité multi-distributions.
- **Architecture** : scripts shell + petit binaire C ; scripts `scripts/*`, config `tigerrc`, outils annexes (tigernocheck, tigexp, tigerrc). Client-serveur optionnel pour la remontée de rapports.
- **Contrôles** : checks classiques : permissions, fichiers SUID/SGID, /etc/passwd shadow, cron, inetd, umask, checks NFS/export…
- **Preuves** : rapports texte datés, niveau d'alerte (ALERT/WARN/FATAL) ; intégration avec syslog/AIDE, messagerie.
- **Profilage** : fichier de config `tigerrc`/`tigernocheck` pour activer/désactiver des scripts.
- **Remédiation** : aucune ; signalement uniquement.
- **Plugins** : scripts shell custom (`scripts/admin/*`), mécanisme de « utilities ».
- **CI** : mode non-interactif possible, sortie texte ; pas de format JSON riche à l'origine.
- **Licence** : GPL (Tiger de l'époque TAMU), redistribution libre.
- **Forces** : très léger, transparent (shell), historique, configurable par scripts.
- **Faiblesses** : vieillissant, portée limitée, pas de benchmarking normé, pas d'index score, sortie verbeuse sans structure machine récente, maintenance réduite, dépendances shell peu robustes face aux distros récentes.
- **URL** : https://savannah.nongnu.org/projects/tiger ; https://github.com/tigerlinux (fork de maintien)
- **Réutilisable** : le modèle « scripts indépendants paramétrables + options on/off » (proche de l'approche par modules de HardAudit).

### osquery
- **Nature** : moteur de collecte SQL (Facebook/Meta, maintenant Linux Foundation). Ce n'est pas un scanner de hardening mais une **table de télémétrie**.
- **Architecture** : daemon `osqueryd` + CLI `osqueryi` ; requêtes SQL sur des tables (processes, file, users, ssh_configs, deb_packages…).
- **Contrôles** : aucun benchmark natif — on écrit ses propres requêtes/packs (ex : `packs/` remédiation CIS communautaires). La conformité se fait par `osqueryi "SELECT..."` custom.
- **Preuves** : résultats tabulaires bruts (JSON via `--json`), audit logs evented.
- **Profilage** : packs/`--enable_monitor`, schedule de requêtes.
- **Remédiation** : aucune dans le moteur ; des packs fournissent des recommandations selon distro.
- **Plugins** : oui, très extensible (tables custom sur macOS/Linux).
- **CI** : excellent démon SQL, `--json` pour pipeline, daemon de collecte continue.
- **Licence** : double licence Apache-2.0/GPL-2.0 pour le code ; tout contenu CIS tiers reste soumis aux termes CIS.
- **Forces** : langage de requête puissant pour investir l'état d'une machine (équivalent « query »), evented logging, écosystème, léger.
- **Faiblesses** : ne « note » pas et ne « remédie » pas ; il **collecte** — il faut écrire les checks de conformité soi-même ; tables parfois instables entre versions ; daemon à gérer.
- **URL** : https://osquery.io ; https://github.com/osquery/osquery (Apache-2.0)
- **Réutilisable** : l'idée de **collecter par requêtes paramétrables** et de **structurer les résultats en tables JSON** — utilisable pour enrichir le `--json` de HardAudit en fabriquant des requêtes.

### Wazuh SCA (Security Configuration Assessment)
- **Nature** : composant du SIEM open source Wazuh (agent déployé) ; évalue la conformité de la configuration.
- **Architecture** : agent (C) collecte, manager agrège, policies **SCA** (YAML : décrivant contrôles, conditions, checks via commandes/CMake/registry), cluster manager pour multi-agent. Analysé dans l'UI Elastic/Wazuh dashboard.
- **Contrôles** : policies par benchmark (CIS, STIG, NIST 800-53, PCI-DSS… ) par OS ; chaque policy a des `checks` avec `condition`/`command` et un **score** calculé.
- **Preuves** : résultats centralisés par check (Pass/Fail/Not applicable), rapport JSON/API, dashboard graphique, alertes SIEM corrélées.
- **Profilage** : choix de policies actives (templates), customization de YAML.
- **Remédiation** : guidance textuelle par check ; certaines procédures dans les policies ; pas de remédiation auto (mais alertes → playbooks).
- **Plugins** : modules du manager ; policies YAML custom = « plugins ».
- **CI** : API REST `/sca/` et sorties JSON ; utilisable dans pipeline mais centré serveur/UI ; agent nécessaire.
- **Licence** : GPLv2 (Wazuh) ; les **policies CIS incluses sont fournies sous licence CIS** (redistribution restreinte) — à vérifier au cas par cas, Wazuh distribue des policies sous licence CIS ; le framework SCA lui-même est libre.
- **Forces** : centralisation multi-déploiement, policies benchmarks normées, intégration SIEM/alertes, score par policy, API.
- **Faiblesses** : infrastructure lourde (agent + manager + UI), pas « sans-install », temps réel continu (pas un audit ponctuel simple), dépendance à un serveur, verbosité.
- **URL** : https://wazuh.com ; https://github.com/wazuh/wazuh (GPLv2)
- **Réutilisable** : le **modèle policy YAML** (checks + condition + command + score) et le **score par policy** sont des idées légitimes ; diffuser ses **propres** checks conformes CIS est autorisé tant qu'on n'embarque pas le contenu propriétaire.

---

## 2. Matrice comparative

| Critère | **HardAudit** | **Lynis** | **OpenSCAP** | **CIS-CAT** | **Tiger** | **osquery** | **Wazuh SCA** |
|---|---|---|---|---|---|---|---|
| Type | Scanner ponctuel | Scanner + hardening index | Framework normé | Scanner CIS officiel | Scanner historique | Collecteur (tables) | Module SCA d'un SIEM |
| Langage cœur | Python (stdlib) | Shell (~300 fichiers) | C + XCCDF/OVAL XML | Java (API) | Shell + C | C++ (daemon/CLI) | C agent |
| Sans installation | Oui (1 fichier) | Non (arborescence) | Non (paquets + content) | Non (JRE + bundle) | Non | Non (daemon) | Non (agent+manager) |
| Poids | 25 Ko / 657 lignes | ~3 Mo | 50 Mo+ | 200 Mo+ (Java) | ~1 Mo | ~10-50 Mo | Lourd (agent+server) |
| Dépendances | 0 | shell, coreutils, configs | compilateur, libs, XML | JRE | shell, binaires | libc++, boost | agent C + manager + UI |
| Nombre de contrôles | ~40 (9 modules) | 300+ | milliers (profils) | par benchmark CIS | ~40-60 | illimité (requêtes) | par policy (centaines) |
| Score/note | Oui /100 (grade A–F) | Hardening Index /100 | % conformité par profil | Pass/Fail par rule | Niveaux ALERT/WARN | Non | Score par policy |
| Référence normée | CIS + ANSSI (citée) | custom (non benchmark) | CIS/STIG/ANSSI (SSG) | CIS officiel | custom/historique | packs custom | CIS/STIG/NIST (policies) |
| Preuve/audit | Commande `Verifier` | Suggestions texte | Résultats OVAL/XML | Rapports HTML/PDF/XML | Rapports texte | JSON tables brutes | Check JSON central |
| Profils | Contexte de ports attendu en cours d'ajout ; pas encore de profil complet | Oui (`.prf`) | Oui (XCCDF profils/vars) | Niveaux 1/2 | tigerrc/tigernocheck | packs/schedule | policies YAML |
| Remédiation | Textuelle (+ `--fix` roadmap) | Suggestions | `--remediate` / fix guide | Guidance + scripts (Pro) | Aucune | Aucune | Guidance + alertes |
| Plugins/ext. | Non (modules fixes) | plugins shell | content custom / OVAL | Non | scripts custom | tables custom | policies YAML |
| Export machine | TXT + JSON | TXT/HTML/JSON | XML ARF/HTML | XML/HTML/PDF/XLSX/JSON | TXT | JSON | JSON (API/SIEM) |
| Adapté CI | Oui (`--json`, simple) | Oui (exit code, `-q`) | Excellent (headless) | Oui (headless | limité | Oui | Oui (via API) |
| Supervision continue | Non (ponctuel) | Ponctuel/planifié | Ponctuel | Ponctuel | Ponctuel | Oui (evented) | Oui (temps réel) |
| Multi-hôte | Non | Non (1 hôte) | Non (1 hôte) | Non (1 hôte) | Non | Multi (query fleet) | Oui (cluster) |
| Licence | **MIT** | **GPLv3** | **LGPL-2.1 / contenu BSD-3-Clause** | **Propriétaire (Lite gratuite)** | **GPL** | **Apache-2.0/GPL-2.0** | **GPLv2 (framework)** |
| Contenu benchmark redistribuable | Oui (propre, cite uniquement) | Oui (propre) | Oui (SSG contenu libre) | Non (CIS fermé) | Oui (propre) | Contenu CIS restreint | Policies CIS restreintes |
| Installation requise | sudo + python3 ✓ | install script | paquets RPM/dpkg | installer Java | script | daemon + config | agent + manager |
| Usage minimal | `sudo python3 hardaudit.py` | `sudo lynis audit system` | `oscap xccdf eval --profile ...` | `CIS-CAT.sh --benchmark ...` | `sudo tiger` | `osqueryi --json "select..."` | agent configuré + policy |
| Forces | Léger, zéro-dep, lisible, preuves, tests | Mature, complet, index connu | Standards, profils, remédiation | Référence CIS, rapports pro | Léger, shell transparent | SQL, evented, extensible | Centralisé, SIEM, scale |
| Faiblesses | Périmètre restreint, pas de supervision continue, pas de profils, pas de remédiation auto | Verbeux, lourd, index non normé, entreprise payante | Très lourd, XML difficile, dépendances | Fermé, payant, poids Java | Vieillissant, pas de score normé, sortie brute | Ne note pas / ne remédie pas, checks à écrire | Lourdeur infra, contenu CIS restreint |

**Positionnement HardAudit** : extrêmement léger et réellement utilisable en un fichier ; son angle différenciant est la philosophie « preuve par commande indépendante + tests anti-faux-positifs ». Le score global n'est pas unique sur le marché et ne doit pas être présenté comme une certification. Contreparties : portée réseau/continue limitée, profils encore embryonnaires et périmètre de contrôles réduit.

---

## 3. Les 5 améliorations à plus fort impact pour HardAudit

> Classées par impact relatif / effort réduit, avec exemple concret et source d'inspiration légitiment réutilisable (concepts génériques, pas de code, pas de contenu CIS copié).

### 1. Ajouter un vrai **moteur de profiling/paramétrage** (`--profile`, `--tailor`, `--level`)
- **Pourquoi** : c'est le premier « saut » que font Lynis (`.prf`), OSCAP (profils XCCDF) et CIS-CAT (Level 1/2). Sans ça, HardAudit est monolithique et ne peut ni désactiver un module, ni limiter la portée (ex : « scan rapide niveau 1 » vs « audit complet niveau 2 »), ni ajouter des règles customeries.
- **Concrètement** : une structure de profil (classe `Profile` ou dict JSON) déclarant quels modules actifs, quelles règles activées, et des variables (ex : `port_ssh_attendu`, `maxauthtries_attendu`) que les fonctions d'audit lisent. Format YAML-ou-JSON simple, chargeable par `--profile`. Un profil par défaut « level1 » activant un sous-ensemble; un « full ».
- **Impact** : ouvre la porte à plusieurs cas d'usage (dev/VM hostil/PCI), aligne sur la norme d'usage des autres outils, augmente le JSON (rend le tout scriptable et réutilisable en CI). Effort faible (refactor des fonctions pour lire un contexte).
- **Inspiration à citer dans le README** : « modèle profils des outils XCCDF/CIS-CAT (concept Level 1/2) ».

### 2. Générer un rapport **HTML riche avec graphiques + historique de score** (en stdlib, sans dépendance)
- **Pourquoi** : les rapports qualité (PDF/XLSX de CIS-CAT, `--report` HTML d'OSCAP, dashboard Wazuh) sont LE différentiateur client. Le TXT/JSON actuel est utile en CLI mais pas présentable à un client ; la roadmap HTML existe déjà.
- **Concrètement** : en pure stdlib, sortie HTML avec un `<details>` par finding, badges de sévérité, barres de progression par module (CSS inline), et une ligne pour **chiffres d'un audit précédent** (comparaison delta si un JSON d'historique est passé en argument). Pas de JavaScript externe → toujours zéro dépendance.
- **Impact** : rend le livrable « filable au client » promis dans le README, et permet de suivre l'amélioration sur plusieurs passes (valeur business). Effort moyen.
- **Inspiration** : la convention « rapport + historique » des outils CI et du dashboard SCA (idée générique, implémentation propre).

### 3. Rendre le **scoring configurable et comparable** (poids par règle, seuils de grade, et sortie d'un **delta de score** en sortie/`--json`)
- **Pourquoi** : OSCAP et Wazuh exposent un % de conformité par profil, et Lynis un hardening index ; aujourd'hui HardAudit fixe dur : poids de modules, pénalités LOW/MEDIUM/HIGH/CRITICAL (-1/-3/-5/-10) et bornes A–F. Tout est en dur dans `Module`/`main`.
- **Concrètement** : rendre le poids, la pénalité et les bornes lisibles depuis le profil ; exposer dans le JSON un `delta` (score vs `--baseline <fichier.json>` précédent) et un `grade`. Ça permet de **sortir un exit code non-zéro si le score baisse** → parfait pour une passe CI « gate » (comme l'exit code de Lynis/OSCAP).
- **Impact** : transforme l'outil de triage en **gate de CI/CD** (roadmap explicitement prévue), et aligne le format JSON sur les sorties normées. Effort modéré.
- **Inspiration** : le concept d'« exit code selon conformité » d'OSCAP/Lynis et de « score par policy » de Wazuh SCA.

### 4. Ajouter une **couche de remédiation sécurisée et contrôlée** (`--fix` avec sauvegarde + dry-run + bannière), déclenchée par les mêmes règles que l'audit
- **Pourquoi** : la remédiation automatique est le point fort d'OSCAP (`--remediate`), et les scripts de remédiation des outils pro. HardAudit n'a que du texte. C'est prévu en roadmap mais fait mieux que prévu.
- **Concrètement** : un champ `fix` optionnel sur `Finding` (une commande idempotente de correction : `chmod 640`, `sed -i` sur `sshd_config` + `systemctl reload`, ajout `iperx` de unattended-upgrades…). `--fix` passe en **dry-run par défaut** (affiche ce qui sera fait), exige `--dry-run` explicite pour appliquer, sauvegarde `.bak` daté, et relance l'audit après pour montrer le **delta**. Chaque correctif vérifié par la commande `verify` existante avant/après (cohérence avec la philosophie « preuves »).
- **Impact** : passe de « diagnostic » à « remédiation », différenciateur majeur vs Lynis/Tiger/osquery (qui ne corrigent pas), et réutilise le `verify` déjà présent. Effort moyen-élevé mais très visible.
- **Inspiration** : `--remediate` + guide de fix d'OpenSCAP (idée générique).

### 5. Couvrir **Deux modules nouveaux à fort besoin sans alourdir** : **Docker/Containers** et **Audit des services/ports actifs hors wildcard** (en mode natif et en dépendance optionnelle)
- **Pourquoi** : le besoin Docker est déjà en roadmap et répond à un standard du marché (context/benchmarks conteneurs). Par ailleurs, la supervision continue multi-hôte est hors de portée d'un script ponctuel, mais on peut rendre HardAudit plus « toujours-pertinent » en détectant les **valeurs sensibles d'écoute et de services** avec moins de faux positifs.
- **Concrètement** :
  - Module « Containers » : si `/var/run/docker.sock` ou un binaire docker est présent, vérifications de bonnes pratiques (pas de `--privileged` flag résiduel détectable, réseau bridge vs host, montages sensibles `/`, UID 0 inutile en image). Reste 100 % stdlib (parse de `docker ps -a` / inspect) et **optionnel** (skip silencieux si aucun dockerd).
  - Enrichir le module Réseau : après avoir identifié les ports wildcard « non surveillés » (déjà bien fait), lister le **programme associé** (`ss -ltnp` → mappage PID→exe) et l'historique des ports exposés dans le `--json`.
- **Impact** : répond à l'adoption massive des conteneurs (couvre un angle concurrentiel des outils lourds sans leur complexité) et fidélise sur un cas réel quotidien. Effort modéré.
- **Inspiration** : les recommendations conteneurs des benchmarks (guide CIS Docker / context), utilisées comme *liste de contrôles conceptuelle*, réécrites en checks propres (pas de copie de contenu).

---

### Lectures/URLs officielles actives (2026)
- Lynis : https://cisofy.com/lynis/ — https://github.com/CISOfy/lynis (GPLv3)
- OpenSCAP : https://www.open-scap.org/ — https://github.com/OpenSCAP/openscap (GPLv2) ; content : https://github.com/ComplianceAsCode/content
- CIS-CAT Pro : https://www.cisecurity.org/cybersecurity-tools/cis-cat/cis-cat-pro ; Lite : https://workbench.cisecurity.org
- Tiger : https://savannah.nongnu.org/projects/tiger ; fork : https://github.com/tigerlinux
- osquery : https://osquery.io — https://github.com/osquery/osquery (Apache-2.0)
- Wazuh SCA : https://wazuh.com — https://github.com/wazuh/wazuh (GPLv2) ; module SCA : https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html
- CIS Benchmarks : https://www.cisecurity.org/cis-benchmarks

*Point de prudence licences : le framework de chaque outil est libre (MIT/GPL/Apache), mais les **contenus de benchmarks CIS** embarqués (CIS-CAT, politiques Wazuh, packs osquery, et les « CIS benchmark Docker ») sont à la licence propriétaire CIS et ne doivent pas être copiés. On ne réutilise que des concepts (profils, niveaux, scoring, remédiation, checks en YAML/XML), jamais la liste de règles ni le texte des benchmarks.*
