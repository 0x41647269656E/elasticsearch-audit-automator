"""Persistance des constats, pour que le rendu ne dépende plus du modèle.

Sans ce fichier, toute évolution du rendu — retirer une section, signaler les
références mortes, changer la synthèse — impose de rappeler le modèle et de
repayer une analyse déjà faite. Les constats sont validés par schéma : rien
n'oblige à les reproduire pour les remettre en forme.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .model import AxeAnalyse, ResultatAxe, Usage

RAPPORT = "rapport.md"
CONSOMMATION = "consommation.json"
CONSTATS = "constats.json"


@dataclass
class Sorties:
    """Les trois fichiers d'une analyse : le document, le coût, la matière."""

    rapport: Path
    consommation: Path
    constats: Path


def output_paths(audit_dir: Path | str, axe: Optional[str] = None) -> Sorties:
    """Un rejeu ne remplace jamais les fichiers du rapport complet.

    L'horodatage permet à plusieurs rejeux du même axe de coexister, ce qui est
    précisément l'usage quand on ajuste un prompt.
    """
    directory = Path(audit_dir)
    if axe is None:
        return Sorties(directory / RAPPORT, directory / CONSOMMATION, directory / CONSTATS)

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    suffixe = f"rejeu-{axe}-{stamp}"
    return Sorties(
        directory / f"rapport-{suffixe}.md",
        directory / f"consommation-{suffixe}.json",
        directory / f"constats-{suffixe}.json",
    )


def dump_axes(axes: Iterable[AxeAnalyse]) -> List[Dict[str, Any]]:
    """Sérialise en clés ASCII : le fichier peut être relu par autre chose que ce code."""
    return [
        {
            "cle": axe.cle,
            "titre": axe.titre,
            "reference": axe.reference,
            "commandes": list(axe.commandes),
            "commandes_declarees": list(axe.commandes_declarees),
            "resultat": axe.resultat.model_dump() if axe.resultat else None,
            "erreur": axe.erreur,
            "agregations": list(axe.agregations),
            "extraits_inverifiables": list(axe.extraits_invérifiables),
            "references_cassees": list(axe.references_cassees),
            "usage": (
                {
                    "input_tokens": axe.usage.input_tokens,
                    "output_tokens": axe.usage.output_tokens,
                    "cache_read_input_tokens": axe.usage.cache_read_input_tokens,
                    "cache_creation_input_tokens": axe.usage.cache_creation_input_tokens,
                }
                if axe.usage
                else None
            ),
            "duree_s": axe.duree_s,
        }
        for axe in axes
    ]


def load_axes(payload: Iterable[Dict[str, Any]]) -> List[AxeAnalyse]:
    axes: List[AxeAnalyse] = []
    for entry in payload:
        resultat = entry.get("resultat")
        usage = entry.get("usage")
        axes.append(
            AxeAnalyse(
                cle=entry["cle"],
                titre=entry["titre"],
                reference=entry.get("reference", ""),
                commandes=list(entry.get("commandes", [])),
                commandes_declarees=list(entry.get("commandes_declarees", [])),
                resultat=ResultatAxe.model_validate(resultat) if resultat else None,
                erreur=entry.get("erreur"),
                agregations=list(entry.get("agregations", [])),
                extraits_invérifiables=list(entry.get("extraits_inverifiables", [])),
                references_cassees=list(entry.get("references_cassees", [])),
                usage=Usage(**usage) if usage else None,
                duree_s=entry.get("duree_s", 0.0),
            )
        )
    return axes


def write_axes(path: Path, axes: Iterable[AxeAnalyse]) -> None:
    payload = {
        "horodatage": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "axes": dump_axes(axes),
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_axes(path: Path) -> List[AxeAnalyse]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_axes(payload["axes"] if isinstance(payload, dict) else payload)
