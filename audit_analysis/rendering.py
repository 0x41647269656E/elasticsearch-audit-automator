"""Rendu Markdown du compte-rendu d'audit.

Ce module ne touche ni au réseau ni au modèle : il transforme des constats en
document. Il se teste donc entièrement avec des constats fabriqués.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .loading import Artefact, Audit
from .model import SEVERITES, AxeAnalyse

def _fence(payload: Any, output_format: str = "json") -> str:
    if output_format == "json":
        return "```json\n" + json.dumps(payload, indent=2, ensure_ascii=False) + "\n```"
    return "```\n" + str(payload) + "\n```"


def _command_block(artefact: Artefact, excerpts: Iterable[str]) -> List[str]:
    """Le bloc exigé avant toute analyse : commande, nœud, horodatage, relevé."""
    meta = artefact.metadata
    lines = [
        f"#### `{artefact.name}`",
        "",
        f"- **environnement** : {meta.get('node') or '_nœud non enregistré_'}",
        f"- **horodatage** : {meta.get('at') or '_inconnu_'}",
        f"- **commande** : `{meta.get('command') or '?'}`",
    ]
    if meta.get("status") is not None:
        lines.append(f"- **statut** : {meta['status']} en {meta.get('duration_ms', '?')} ms")
    lines.append(f"- **relevé complet** : `{artefact.path.name}`, livré avec le rapport")
    lines.append("")

    excerpts = list(excerpts)
    if excerpts:
        lines.append("Extraits retenus pour cet axe :")
        lines.append("")
        for fragment in excerpts:
            lines.append(_fence(fragment))
            lines.append("")
    return lines


def _summary_table(axes: List[AxeAnalyse]) -> List[str]:
    header = "| Axe | " + " | ".join(SEVERITES) + " | Constats | État |"
    sep = "|---" * (len(SEVERITES) + 3) + "|"
    lines = ["## Synthèse", "", header, sep]
    totals = {s: 0 for s in SEVERITES}

    for axe in axes:
        counts = {s: 0 for s in SEVERITES}
        for constat in axe.constats:
            counts[constat.severite] += 1
            totals[constat.severite] += 1
        if axe.erreur:
            etat = "non évalué"
        elif not axe.constats and axe.resultat and axe.resultat.angles_morts:
            etat = "angles morts"
        else:
            etat = "évalué"
        lines.append(
            f"| {axe.titre} | "
            + " | ".join(str(counts[s]) for s in SEVERITES)
            + f" | {len(axe.constats)} | {etat} |"
        )

    lines.append(
        "| **Total** | "
        + " | ".join(f"**{totals[s]}**" for s in SEVERITES)
        + f" | **{sum(totals.values())}** | |"
    )
    lines.append("")
    return lines


def _axis_section(axe: AxeAnalyse, audit: Audit,
                  excerpts_by_command: Dict[str, List[str]]) -> List[str]:
    lines = [f"## Axe — {axe.titre}", "", f"Référence : <{axe.reference}>", ""]

    if axe.agregations:
        lines += [
            "> Artefacts **agrégés** avant analyse pour tenir dans la fenêtre de contexte : "
            + ", ".join(f"`{a}`" for a in axe.agregations)
            + ". Le modèle a vu une forme dense, pas l'énumération complète.",
            "",
        ]

    if axe.erreur:
        lines += [f"> **Axe non évalué** : {axe.erreur}", ""]
        return lines

    for name in axe.commandes:
        artefact = audit.artefacts.get(name)
        if artefact is None:
            continue
        lines += _command_block(artefact, excerpts_by_command.get(name, []))

    lines += ["**Constats**", ""]
    if not axe.constats:
        lines += ["_Aucun constat pour cet axe._", ""]
    for i, constat in enumerate(axe.constats, start=1):
        lines += [
            f"##### {i}. {constat.constat}",
            "",
            f"- **valeur relevée** : {constat.valeur_relevee}",
            f"- **sévérité** : **{constat.severite}**",
            f"- **impact** : {constat.impact}",
            f"- **remédiation** : {constat.remediation}",
            f"- **référence** : <{constat.reference}>",
            "",
        ]

    if axe.extraits_invérifiables:
        lines += [
            "> **Extraits invérifiables** — les fragments suivants n'ont pas été retrouvés "
            "dans l'artefact source et ne doivent pas être tenus pour des preuves :",
            "",
        ]
        lines += [f"> - `{fragment}`" for fragment in axe.extraits_invérifiables]
        lines.append("")

    angles = axe.resultat.angles_morts if axe.resultat else []
    lines += ["**Angles morts**", ""]
    lines += ([f"- {a}" for a in angles] if angles else ["_Aucun._"])
    lines.append("")
    return lines


def render_report(
    audit: Audit,
    axes: List[AxeAnalyse],
    excerpts_by_command: Optional[Dict[str, List[str]]] = None,
) -> str:
    excerpts_by_command = excerpts_by_command or {}

    lines = [
        f"# Audit Elasticsearch — {audit.cluster_name or 'cluster inconnu'}",
        "",
        f"- **client** : {audit.infos.get('client_name') or '—'}",
        f"- **typologie** : {audit.typology or '—'}",
        f"- **nœud interrogé** : {audit.node_name or '_non enregistré_'}",
        f"- **collecte** : {audit.timestamp or '—'}",
        "",
    ]

    if not audit.has_metadata:
        lines += [
            "> Ce dossier d'audit est antérieur à l'enregistrement des métadonnées par "
            "commande. Les blocs ci-dessous portent l'**horodatage global** de la collecte "
            "et non celui de chaque commande, et le nœud interrogé peut être inconnu.",
            "",
        ]

    lines += _summary_table(axes)
    for axe in axes:
        lines += _axis_section(axe, audit, excerpts_by_command)

    return "\n".join(lines).rstrip() + "\n"
