"""Analyse un dossier d'audit et produit le compte-rendu Markdown.

    python analyse.py data/2026-07-31_19-01-23-acme-audit-es8

Appelé automatiquement par main.py à la fin d'une collecte, ou à la main sur un
dossier existant.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from audit_analysis import analysis, loading, rendering
from audit_analysis.client import AnthropicCaller, resolve_credentials

RAPPORT = "rapport.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyse d'un dossier d'audit Elasticsearch")
    parser.add_argument("audit_dir", help="Dossier d'audit produit par main.py")
    parser.add_argument("--commands", default="commands.json", help="Chemin de commands.json")
    parser.add_argument("--model", default=None, help="Modèle à utiliser")
    parser.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        default=None,
        help="Profondeur de raisonnement (défaut : high)",
    )
    parser.add_argument(
        "--budget-tokens",
        type=int,
        default=analysis.DEFAULT_BUDGET_TOKENS,
        help="Seuil au-delà duquel les artefacts d'un axe sont agrégés",
    )
    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="Désactive le repli serveur en cas de refus du modèle",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="N'appelle pas le modèle : produit la structure du rapport sans constats",
    )
    return parser.parse_args()


class DryRunCaller:
    """Ne contacte rien ; sert à valider la forme du rapport sans dépenser de jetons."""

    def complete(self, system, user, schema):
        return analysis.ModelOutcome(data={"constats": [], "angles_morts": [
            "Exécution à blanc : aucun appel au modèle n'a été fait."
        ]})


def main() -> int:
    args = parse_args()
    audit_dir = Path(args.audit_dir)
    if not audit_dir.is_dir():
        print(f"Dossier d'audit introuvable : {audit_dir}", file=sys.stderr)
        return 1

    commands_meta = json.loads(Path(args.commands).read_text(encoding="utf-8"))
    audit = loading.load_audit(audit_dir)
    axes = analysis.build_axes(commands_meta, audit)

    print(f"Audit    : {audit.cluster_name} ({audit.typology}) — {len(audit.artefacts)} artefacts")
    if audit.failures:
        print(f"Échecs   : {len(audit.failures)} commande(s) — déclarées comme angles morts")
    if not audit.has_metadata:
        print("Attention: dossier antérieur aux métadonnées par commande (horodatage global)")

    if args.dry_run:
        caller = DryRunCaller()
        print("Mode     : exécution à blanc, aucun appel au modèle\n")
    else:
        probleme = resolve_credentials()
        if probleme:
            print(probleme, file=sys.stderr)
            return 1
        kwargs = {"fallback": not args.no_fallback}
        if args.model:
            kwargs["model"] = args.model
        if args.effort:
            kwargs["effort"] = args.effort
        caller = AnthropicCaller(**kwargs)
        print(f"Modèle   : {caller.model} (effort {caller.effort})\n")

    depart = time.perf_counter()
    resultats = []
    for i, axe in enumerate(axes, start=1):
        print(f"[{i}/{len(axes)}] {axe.titre} — {len(axe.commandes)} artefact(s)…", flush=True)
        resultat = analysis.analyse_axis(caller, axe, audit, commands_meta, args.budget_tokens)
        resultats.append(resultat)
        if resultat.agregations:
            print(f"        agrégé pour tenir dans la fenêtre : {', '.join(resultat.agregations)}")
        if resultat.erreur:
            print(f"        NON ÉVALUÉ : {resultat.erreur}")
        else:
            print(f"        {len(resultat.constats)} constat(s)")
        if resultat.extraits_invérifiables:
            print(f"        {len(resultat.extraits_invérifiables)} extrait(s) invérifiable(s)")

    rapport = rendering.render_report(audit, resultats)
    chemin = audit_dir / RAPPORT
    chemin.write_text(rapport, encoding="utf-8")

    total = sum(len(r.constats) for r in resultats)
    non_evalues = sum(1 for r in resultats if r.erreur)
    print(f"\nRapport écrit : {chemin}")
    print(f"{total} constat(s) sur {len(axes) - non_evalues}/{len(axes)} axes évalués "
          f"en {time.perf_counter() - depart:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
