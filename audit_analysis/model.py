"""Schéma des constats produits par le modèle.

Les champs reprennent `restitution.champs_constat` de commands.json : un constat
qui n'en porte pas la totalité n'est pas exploitable dans la synthèse.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field

SEVERITES = ("CRITIQUE", "MAJEUR", "MINEUR", "INFORMATIF")


class Extrait(BaseModel):
    commande: str = Field(description="Nom de la commande d'où provient le fragment")
    fragment: str = Field(description="Fragment exact recopié depuis l'artefact")


class Constat(BaseModel):
    constat: str
    valeur_relevee: str
    severite: Literal["CRITIQUE", "MAJEUR", "MINEUR", "INFORMATIF"]
    impact: str
    remediation: str
    reference: str
    extraits: List[Extrait] = Field(default_factory=list)


class ResultatAxe(BaseModel):
    constats: List[Constat] = Field(default_factory=list)
    angles_morts: List[str] = Field(default_factory=list)


def _tighten(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object":
            node["additionalProperties"] = False
            node["required"] = list(node.get("properties", {}))
        for value in node.values():
            _tighten(value)
    elif isinstance(node, list):
        for value in node:
            _tighten(value)


def strict_schema(model: type[BaseModel]) -> dict:
    """Schéma JSON accepté par la sortie structurée.

    Pydantic omet `additionalProperties` — l'API rejette alors la requête en
    400 — et sort de `required` tout champ pourvu d'une valeur par défaut, que
    la sortie structurée veut pourtant voir listé. On resserre les deux, sur
    une copie : le schéma de Pydantic n'est pas modifié.
    """
    schema = deepcopy(model.model_json_schema())
    _tighten(schema)
    return schema


@dataclass
class AxeAnalyse:
    """Ce qu'on sait d'un axe après analyse, succès ou échec."""

    cle: str
    titre: str
    reference: str
    commandes: List[str]
    # Toutes les commandes déclarées pour cet axe, y compris celles qui ont
    # échoué et n'ont donc produit aucun artefact : ce sont elles qui portent
    # les angles morts.
    commandes_declarees: List[str] = field(default_factory=list)
    resultat: Optional[ResultatAxe] = None
    erreur: Optional[str] = None
    agregations: List[str] = field(default_factory=list)
    extraits_invérifiables: List[str] = field(default_factory=list)

    @property
    def constats(self) -> List[Constat]:
        return self.resultat.constats if self.resultat else []
