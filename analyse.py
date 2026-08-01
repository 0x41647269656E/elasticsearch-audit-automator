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

from dotenv import load_dotenv

from audit_analysis import analysis, loading, persistence, rendering, usage
from audit_analysis.client import AnthropicCaller, resolve_credentials


def load_credentials(env_file="./.env") -> None:
    """Charge .env comme le fait main.py.

    Sans cet appel, une clé placée dans .env — ce que documente le projet —
    resterait invisible pour le SDK, qui ne lit que l'environnement.
    Une variable déjà exportée l'emporte sur le fichier.
    """
    load_dotenv(env_file, override=False)


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
        "--axe",
        default=None,
        help="Rejoue l'analyse sur ce seul axe ; écrit à côté du rapport complet, "
             "sans l'écraser",
    )
    parser.add_argument(
        "--rerender",
        nargs="?",
        const=True,
        default=None,
        metavar="CONSTATS",
        help="Régénère le rapport depuis constats.json, sans aucun appel au modèle "
             "ni dépense. Accepte le chemin d'un autre fichier de constats.",
    )
    parser.add_argument(
        "--no-check-refs",
        action="store_true",
        help="N'interroge pas les URL citées par l'analyse pour vérifier qu'elles résolvent",
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

    if args.rerender:
        source = (
            Path(args.rerender) if isinstance(args.rerender, str)
            else persistence.output_paths(audit_dir).constats
        )
        if not source.is_file():
            print(f"Fichier de constats introuvable : {source}", file=sys.stderr)
            print("Il est produit par une analyse ; aucun rendu n'est possible sans lui.",
                  file=sys.stderr)
            return 1
        resultats = persistence.read_axes(source)

        # Les vérifications locales sont gratuites et ont pu s'améliorer depuis
        # l'analyse : les rejouer fait profiter un rapport ancien des correctifs
        # sans rappeler le modèle.
        for axe in resultats:
            if axe.resultat:
                axe.extraits_invérifiables = analysis.verify_excerpts(axe.resultat, audit)
        signales = sum(len(a.extraits_invérifiables) for a in resultats)
        print(f"Extraits revérifiés : {signales} signalé(s)")

        chemin = persistence.output_paths(audit_dir, args.axe).rapport
        chemin.write_text(rendering.render_report(audit, resultats), encoding="utf-8")
        print(f"Rapport régénéré depuis {source.name} : {chemin}")
        print(f"{sum(len(r.constats) for r in resultats)} constat(s) — aucun appel au modèle")
        return 0

    if args.axe:
        connus = [a.cle for a in axes]
        if args.axe not in connus:
            print(f"Axe inconnu : {args.axe}. Axes disponibles : {', '.join(connus)}",
                  file=sys.stderr)
            return 1
        axes = [a for a in axes if a.cle == args.axe]

    print(f"Audit    : {audit.cluster_name} ({audit.typology}) — {len(audit.artefacts)} artefacts")
    if audit.failures:
        print(f"Échecs   : {len(audit.failures)} commande(s) — déclarées comme angles morts")
    if not audit.has_metadata:
        print("Attention: dossier antérieur aux métadonnées par commande (horodatage global)")

    if args.dry_run:
        caller = DryRunCaller()
        print("Mode     : exécution à blanc, aucun appel au modèle\n")
    else:
        load_credentials()
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

    if not args.no_check_refs:
        print("\nVérification des références citées…", flush=True)
        analysis.verify_references(resultats)
        cassees = sum(len(r.references_cassees) for r in resultats)
        print(f"        {cassees} référence(s) non résolue(s)")

    duree = time.perf_counter() - depart
    sorties = persistence.output_paths(audit_dir, args.axe)

    # Les constats d'abord : ce sont eux qui ont coûté, et eux seuls permettent
    # de refaire le rendu plus tard sans repayer une analyse déjà faite.
    persistence.write_axes(sorties.constats, resultats)
    sorties.rapport.write_text(rendering.render_report(audit, resultats), encoding="utf-8")

    modele = getattr(caller, "model", "—")
    effort = getattr(caller, "effort", "—")
    conso = usage.build_report(modele, effort, resultats, duree)
    sorties.consommation.write_text(
        json.dumps(conso, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    total = conso["total"]
    print(f"\nRapport      : {sorties.rapport}")
    print(f"Constats     : {sorties.constats}")
    print(f"Consommation : {sorties.consommation}")
    print(f"{total['constats']} constat(s) sur "
          f"{total['axes_evalues']}/{total['axes_total']} axes évalués en {duree:.0f} s")
    print(f"Jetons       : {total['input_tokens']:,} en entrée, "
          f"{total['output_tokens']:,} en sortie (raisonnement inclus)")
    if total["cout_usd"] is not None:
        print(f"Coût mesuré  : {total['cout_usd']:.2f} $")
    return 0


if __name__ == "__main__":
    sys.exit(main())
