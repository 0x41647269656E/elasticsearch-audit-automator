"""Comptabilité de la consommation, écrite à côté du rapport.

Le rapport dit ce que le cluster a de travers ; ce fichier dit ce que l'avoir
découvert a coûté. Les deux se lisent séparément, et une relance sur un seul
axe n'écrase ni l'un ni l'autre.
"""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from .model import AxeAnalyse, Usage

RAPPORT = "rapport.md"
CONSOMMATION = "consommation.json"

# Tarifs en dollars par million de jetons. Table locale : elle peut dériver des
# tarifs publiés, d'où un coût absent plutôt que faux pour un modèle inconnu.
TARIFS: Dict[str, Dict[str, float]] = {
    "claude-opus-5": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25},
    "claude-opus-4-8": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25},
    "claude-fable-5": {"input": 10.0, "output": 50.0, "cache_read": 1.0, "cache_write": 12.5},
    "claude-sonnet-5": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25},
}


def cost_usd(usage: Usage, model: str) -> Optional[float]:
    """Coût d'un appel, ou None si le tarif du modèle n'est pas connu ici."""
    tarif = TARIFS.get(model)
    if tarif is None:
        return None
    return (
        usage.input_tokens / 1e6 * tarif["input"]
        + usage.output_tokens / 1e6 * tarif["output"]
        + usage.cache_read_input_tokens / 1e6 * tarif["cache_read"]
        + usage.cache_creation_input_tokens / 1e6 * tarif["cache_write"]
    )


def _entry(axe: AxeAnalyse, model: str) -> Dict[str, Any]:
    u = axe.usage or Usage()
    return {
        "titre": axe.titre,
        "etat": "non évalué" if axe.erreur else "évalué",
        "constats": len(axe.constats),
        "input_tokens": u.input_tokens,
        "output_tokens": u.output_tokens,
        "cache_read_input_tokens": u.cache_read_input_tokens,
        "cache_creation_input_tokens": u.cache_creation_input_tokens,
        "duree_s": round(axe.duree_s, 1),
        "cout_usd": cost_usd(u, model),
        "agregations": axe.agregations,
        "erreur": axe.erreur,
    }


def build_report(
    model: str, effort: str, axes: Iterable[AxeAnalyse], duree_s: float
) -> Dict[str, Any]:
    axes = list(axes)
    total = Usage()
    for axe in axes:
        if axe.usage:
            total = total + axe.usage

    return {
        "horodatage": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "modele": model,
        "effort": effort,
        "duree_s": round(duree_s, 1),
        "axes": {axe.cle: _entry(axe, model) for axe in axes},
        "total": {
            "input_tokens": total.input_tokens,
            "output_tokens": total.output_tokens,
            "cache_read_input_tokens": total.cache_read_input_tokens,
            "cache_creation_input_tokens": total.cache_creation_input_tokens,
            "cout_usd": cost_usd(total, model),
            "axes_evalues": sum(1 for a in axes if not a.erreur),
            "axes_total": len(axes),
            "constats": sum(len(a.constats) for a in axes),
        },
        "_tarifs": TARIFS.get(model),
    }


def output_paths(audit_dir: Path | str, axe: Optional[str] = None) -> Tuple[Path, Path]:
    """Chemins du rapport et de la consommation.

    Un rejeu porte le nom de l'axe et un horodatage : il ne remplace jamais le
    rapport complet, et deux rejeux successifs coexistent pour être comparés.
    """
    directory = Path(audit_dir)
    if axe is None:
        return directory / RAPPORT, directory / CONSOMMATION

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    suffixe = f"rejeu-{axe}-{stamp}"
    return directory / f"rapport-{suffixe}.md", directory / f"consommation-{suffixe}.json"
