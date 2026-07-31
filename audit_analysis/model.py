"""Schéma des constats produits par le modèle.

Les champs reprennent `restitution.champs_constat` de commands.json : un constat
qui n'en porte pas la totalité n'est pas exploitable dans la synthèse.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional

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


@dataclass
class AxeAnalyse:
    """Ce qu'on sait d'un axe après analyse, succès ou échec."""

    cle: str
    titre: str
    reference: str
    commandes: List[str]
    resultat: Optional[ResultatAxe] = None
    erreur: Optional[str] = None
    agregations: List[str] = field(default_factory=list)
    extraits_invérifiables: List[str] = field(default_factory=list)

    @property
    def constats(self) -> List[Constat]:
        return self.resultat.constats if self.resultat else []
