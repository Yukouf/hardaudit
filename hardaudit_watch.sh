#!/usr/bin/env bash
# =============================================================================
# hardaudit_watch.sh — surveillance hebdo (installée par install.sh)
# Audit complet + historique des notes + alerte si note < seuil.
# =============================================================================
set -euo pipefail

SEUIL=80
BASE=/opt/hardaudit
LOG_DIR=/var/log/hardaudit
TSTAMP=$(date +%Y-%m-%d)

mkdir -p "$LOG_DIR"

sudo python3 "$BASE/hardaudit.py" -o "$LOG_DIR/rapport_$TSTAMP.txt" >/dev/null 2>&1 || true

SCORE=$(grep -oE "SCORE FINAL : [0-9]+" "$LOG_DIR/rapport_$TSTAMP.txt" 2>/dev/null | grep -oE "[0-9]+$" || echo "0")

echo "$TSTAMP,$SCORE,$(hostname)" >> "$LOG_DIR/historique.csv"

if [ "${SCORE:-0}" -lt "$SEUIL" ]; then
  echo "🔴 HardAudit $(hostname) : note $SCORE/100 (seuil $SEUIL) — $TSTAMP"
  echo "Rapport : $LOG_DIR/rapport_$TSTAMP.txt"
  if command -v mail >/dev/null 2>&1; then
    echo "HardAudit $(hostname) : note $SCORE/100 — sous le seuil $SEUIL. Voir $LOG_DIR/rapport_$TSTAMP.txt" \
      | mail -s "🔴 HardAudit — $SCORE/100 sur $(hostname)" root 2>/dev/null || true
  fi
  exit 1
fi

echo "🟢 HardAudit $(hostname) : note $SCORE/100 — conforme"
exit 0
