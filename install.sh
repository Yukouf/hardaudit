#!/usr/bin/env bash
# =============================================================================
# HardAudit — installateur universel (1 commande, depuis n'importe quelle VM)
# -----------------------------------------------------------------------------
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/Yukouf/hardaudit/main/install.sh | sudo bash
#
# Options :
#   --no-cron   n'installe pas la surveillance hebdomadaire
#   --no-audit  n'exécute pas le premier audit à la fin
#   --dir PATH  dossier d'installation (défaut : /opt/hardaudit)
#
# Ce que fait l'installateur :
#   1. vérifie / installe Python 3 si absent (apt, dnf, yum ou apk)
#   2. installe hardaudit (l'auditeur) + hardaudit_watch (la surveillance)
#   3. planifie un audit automatique chaque lundi à 7h (sauf --no-cron)
#   4. lance le premier audit et affiche la note
# =============================================================================
set -euo pipefail

BASE_URL="https://raw.githubusercontent.com/Yukouf/hardaudit/main"
INSTALL_DIR="/opt/hardaudit"
DO_CRON=1
DO_AUDIT=1

for arg in "$@"; do
  case "$arg" in
    --no-cron)  DO_CRON=0 ;;
    --no-audit) DO_AUDIT=0 ;;
    --dir=*)    INSTALL_DIR="${arg#--dir=}" ;;
    *) echo "Option inconnue : $arg" >&2; exit 2 ;;
  esac
done

# ── 0. Droits root ───────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ Lance avec sudo : curl -fsSL ... | sudo bash" >&2
  exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  HardAudit — installation                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── 1. Python 3 (seule dépendance) ───────────────────────────────────────────
if command -v python3 >/dev/null 2>&1; then
  echo "✓ Python 3 déjà présent ($(python3 --version 2>&1))"
else
  echo "… Python 3 absent — installation…"
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q python3
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q python3
  elif command -v apk     >/dev/null 2>&1; then apk add --no-cache python3
  else echo "❌ Aucun gestionnaire de paquets reconnu (apt/dnf/yum/apk) — installe Python 3 manuellement." >&2; exit 1
  fi
  echo "✓ Python 3 installé"
fi

# ── 2. Téléchargement des fichiers ───────────────────────────────────────────
echo "… Téléchargement dans $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"
curl -fsSL "$BASE_URL/hardaudit.py" -o "$INSTALL_DIR/hardaudit.py"
curl -fsSL "$BASE_URL/hardaudit_watch.sh" -o "$INSTALL_DIR/hardaudit_watch.sh"
chmod 755 "$INSTALL_DIR/hardaudit.py" "$INSTALL_DIR/hardaudit_watch.sh"

# Lien global : `sudo hardaudit` depuis n'importe quel dossier
ln -sf "$INSTALL_DIR/hardaudit.py" /usr/local/bin/hardaudit
chmod 755 /usr/local/bin/hardaudit 2>/dev/null || true
echo "✓ hardaudit installé (commande : sudo hardaudit)"

# ── 3. Surveillance hebdomadaire (cron) ──────────────────────────────────────
if [ "$DO_CRON" -eq 1 ]; then
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -v "hardaudit_watch.sh" ; echo "0 7 * * 1 $INSTALL_DIR/hardaudit_watch.sh" ) | crontab -
    echo "✓ Audit automatique planifié : chaque lundi à 7h"
  else
    echo "⚠ crontab absent — ajoute manuellement : 0 7 * * 1 $INSTALL_DIR/hardaudit_watch.sh"
  fi
fi

# ── 4. Premier audit ─────────────────────────────────────────────────────────
if [ "$DO_AUDIT" -eq 1 ]; then
  echo ""
  echo "… Premier audit…"
  python3 "$INSTALL_DIR/hardaudit.py" || true
fi

# ── Message final (explication simple) ───────────────────────────────────────
cat <<EOF

═══════════════════════════════════════════════════════════════
  C'EST FAIT ✅ — ce que tu as maintenant sur cette machine :

  HardAudit, c'est le contrôle technique du serveur.
  Comme pour une voiture, il vérifie 9 points de sécurité
  (accès, mots de passe, pare-feu, mises à jour, ports...)
  et donne une note sur 100.

  • Note ≥ 80/100  → machine en règle (vert)
  • Note <  80/100 → des points à corriger (rouge)

  Chaque lundi à 7h, il se re-contrôle tout seul, garde
  l'historique des notes, et alerte si la note baisse.

  Pour relancer un contrôle à la main :  sudo hardaudit
  Pour lire le rapport :                  sudo hardaudit -o rapport.txt
═══════════════════════════════════════════════════════════════
EOF
exit 0
