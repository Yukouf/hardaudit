#!/usr/bin/env python3
"""hardaudit_collect.py — collecte multi-machines et agrégation des audits HardAudit.

Usage :
  # Machine locale uniquement
  sudo python3 hardaudit_collect.py --local

  # Machines locales + distantes (via SSH, clé configurée)
  sudo python3 hardaudit_collect.py --local --hosts admin@vps1 admin@vps2

  # Distantes uniquement
  python3 hardaudit_collect.py --hosts admin@vps1 admin@vps2

  # Dossier de sortie personnalisé
  python3 hardaudit_collect.py --local --out /data/hardaudit

Sorties (dans le dossier de sortie, défaut ./hardaudit_data/) :
  - dataset_<AAAAMMJJ>.json  : tous les audits bruts (modules + findings détaillés)
  - synthese_<AAAAMMJJ>.csv  : tableau plat hôte x score x sévérités (prêt pandas/Excel)
"""
import argparse
import csv
import datetime
import json
import os
import subprocess
import sys

def run_local():
    """Exécute hardaudit --json sur la machine courante."""
    try:
        out = subprocess.run(
            ["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "hardaudit.py"), "--json"],
            capture_output=True, text=True, timeout=180,
        )
        if out.returncode != 0:
            print(f"  ⚠ audit local : exit {out.returncode}", file=sys.stderr)
        return json.loads(out.stdout)
    except Exception as e:
        print(f"  ⚠ audit local échoué : {e}", file=sys.stderr)
        return None

def run_remote(target):
    """Exécute hardaudit --json sur un hôte distant via SSH."""
    try:
        out = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target,
             "sudo python3 /opt/hardaudit/hardaudit.py --json 2>/dev/null || sudo hardaudit --json 2>/dev/null"],
            capture_output=True, text=True, timeout=180,
        )
        if out.returncode != 0:
            print(f"  ⚠ {target} : SSH/audit échoué ({out.returncode})", file=sys.stderr)
            return None
        return json.loads(out.stdout)
    except Exception as e:
        print(f"  ⚠ {target} : {e}", file=sys.stderr)
        return None

def main():
    ap = argparse.ArgumentParser(description="Collecte multi-machines des audits HardAudit")
    ap.add_argument("--local", action="store_true", help="auditer la machine courante")
    ap.add_argument("--hosts", nargs="*", default=[], help="hôtes distants (user@host)")
    ap.add_argument("--out", default="hardaudit_data", help="dossier de sortie")
    args = ap.parse_args()

    if not args.local and not args.hosts:
        ap.error("rien à faire : ajoute --local et/ou --hosts")

    os.makedirs(args.out, exist_ok=True)
    stamp = datetime.date.today().strftime("%Y%m%d")
    audits = []
    targets = []
    if args.local:
        targets.append("(local)")
        r = run_local()
        if r:
            audits.append(r)
    for h in args.hosts:
        targets.append(h)
        r = run_remote(h)
        if r:
            audits.append(r)

    print(f"Collecte terminée : {len(audits)}/{len(targets)} machines auditées")

    if not audits:
        print("Aucun audit collecté — rien à écrire.")
        sys.exit(1)

    # ── Dataset JSON complet ─────────────────────────────────────────────
    dataset = {
        "generated": datetime.datetime.now().isoformat(),
        "count": len(audits),
        "hosts": audits,
    }
    json_path = os.path.join(args.out, f"dataset_{stamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)
    print(f"✅ dataset JSON : {json_path}")

    # ── Synthèse CSV (hôte x score x sévérités) ─────────────────────────
    csv_path = os.path.join(args.out, f"synthese_{stamp}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["host", "date", "score", "max", "grade",
                    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "total"])
        for a in audits:
            s = a.get("summary", {})
            w.writerow([a.get("host"), a.get("date"), a.get("score"), a.get("max"),
                        a.get("grade"), s.get("INFO", 0), s.get("LOW", 0),
                        s.get("MEDIUM", 0), s.get("HIGH", 0), s.get("CRITICAL", 0),
                        s.get("total", 0)])
    print(f"✅ synthèse CSV : {csv_path}")

    # ── Tableau récapitulatif ────────────────────────────────────────────
    print("\n=== RÉCAPITULATIF ===")
    print(f"{'hôte':<28} {'score':>5} {'grade':>5}  H/C")
    for a in audits:
        s = a.get("summary", {})
        print(f"{a.get('host','?')[:28]:<28} {a.get('score',0):>5} {a.get('grade','?'):>5}  "
              f"{s.get('HIGH',0)}/{s.get('CRITICAL',0)}")

if __name__ == "__main__":
    main()
