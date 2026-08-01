"""Regroupement par axe, appel du modèle, vérification des extraits.

Seule unité qui touche au réseau, et encore : l'appel passe par un objet
`caller` injecté, ce qui rend toute la logique testable hors ligne.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from .loading import Audit
from .model import AxeAnalyse, ResultatAxe, strict_schema
from .reduction import fit_to_budget

# Marge sous la fenêtre du modèle : la sortie et le prompt système comptent aussi.
DEFAULT_BUDGET_TOKENS = 700_000


@dataclass
class ModelOutcome:
    """Résultat d'un appel : des données, un refus, ou rien."""

    data: Optional[Dict[str, Any]] = None
    refusal: Optional[str] = None


class Caller(Protocol):
    def complete(self, system: str, user: str, schema: Dict[str, Any]) -> ModelOutcome: ...


def build_axes(commands_meta: Dict[str, Any], audit: Audit) -> List[AxeAnalyse]:
    """Un axe par entrée de commands.json, limité aux commandes réellement collectées."""
    collectees: Dict[str, List[str]] = {cle: [] for cle in commands_meta.get("axes", {})}
    declarees: Dict[str, List[str]] = {cle: [] for cle in commands_meta.get("axes", {})}
    for command in commands_meta.get("commands", []):
        for cle in command.get("axes", []):
            if cle not in declarees:
                continue
            declarees[cle].append(command["name"])
            if command["name"] in audit.artefacts:
                collectees[cle].append(command["name"])

    return [
        AxeAnalyse(
            cle=cle,
            titre=body.get("titre", cle),
            reference=body.get("reference", ""),
            commandes=collectees.get(cle, []),
            commandes_declarees=declarees.get(cle, []),
        )
        for cle, body in commands_meta.get("axes", {}).items()
    ]


def axis_failures(axe: AxeAnalyse, audit: Audit) -> Dict[str, str]:
    """Échecs des commandes rattachées à cet axe — les angles morts à déclarer."""
    declarees = set(axe.commandes_declarees)
    return {n: msg for n, msg in audit.failures.items() if n in declarees}


def _normalise(text: str) -> str:
    return re.sub(r"\s+", "", text)


def verify_excerpts(resultat: ResultatAxe, audit: Audit) -> List[str]:
    """Retourne les fragments introuvables dans leur artefact d'origine.

    Un modèle peut recopier de travers. Un constat qui s'appuie sur un fragment
    inexistant reste dans le rapport, mais signalé : un audit ne présente pas
    une citation approximative comme une preuve.
    """
    introuvables: List[str] = []
    serialise: Dict[str, str] = {}

    for constat in resultat.constats:
        for extrait in constat.extraits:
            artefact = audit.artefacts.get(extrait.commande)
            if artefact is None:
                introuvables.append(f"{extrait.commande} : commande absente du dossier d'audit")
                continue
            if extrait.commande not in serialise:
                data = artefact.data
                brut = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
                serialise[extrait.commande] = _normalise(brut)
            if _normalise(extrait.fragment) not in serialise[extrait.commande]:
                introuvables.append(f"{extrait.commande} : {extrait.fragment}")

    return introuvables


def _artefacts_for(axe: AxeAnalyse, audit: Audit) -> Dict[str, Any]:
    return {nom: audit.artefacts[nom].data for nom in axe.commandes if nom in audit.artefacts}


def build_system_prompt(audit: Audit, commands_meta: Dict[str, Any]) -> str:
    """Préfixe identique pour les dix axes — c'est lui qui bénéficie du cache."""
    restitution = commands_meta.get("restitution", {})
    return "\n".join(
        [
            "Tu es un auditeur Elasticsearch. Tu produis des constats factuels et vérifiables.",
            "",
            restitution.get("consigne_globale", ""),
            "",
            "Contexte de l'audit :",
            json.dumps(audit.infos, indent=2, ensure_ascii=False),
        ]
    )


def build_user_prompt(
    axe: AxeAnalyse,
    audit: Audit,
    commands_meta: Dict[str, Any],
    artefacts: Dict[str, Any],
    failures: Dict[str, str],
) -> str:
    prompts = {c["name"]: c.get("prompt", "") for c in commands_meta.get("commands", [])}
    axe_body = commands_meta.get("axes", {}).get(axe.cle, {})

    parts = [
        f"# Axe : {axe.titre}",
        f"Référence : {axe_body.get('reference', '')}",
        "",
        "## Consigne de l'axe",
        axe_body.get("prompt", ""),
        "",
        "## Relevés",
    ]
    for nom, data in artefacts.items():
        meta = audit.artefacts[nom].metadata
        parts += [
            f"### {nom}",
            f"commande : {meta.get('command')} — nœud : {meta.get('node')} — à {meta.get('at')}",
            f"ce qu'il faut en relever : {prompts.get(nom, '')}",
            "```json",
            data if isinstance(data, str) else json.dumps(data, ensure_ascii=False),
            "```",
            "",
        ]

    if failures:
        parts += ["## Commandes en échec — angles morts à déclarer", ""]
        parts += [f"- {nom} : {msg.strip()[:400]}" for nom, msg in failures.items()]
        parts.append("")

    parts += [
        "Chaque constat doit citer, dans `extraits`, le fragment exact recopié depuis "
        "l'un des relevés ci-dessus. Ne cite jamais un fragment que tu n'as pas sous les yeux.",
    ]
    return "\n".join(parts)


def analyse_axis(
    caller: Caller,
    axe: AxeAnalyse,
    audit: Audit,
    commands_meta: Dict[str, Any],
    budget_tokens: int = DEFAULT_BUDGET_TOKENS,
) -> AxeAnalyse:
    """Analyse un axe. Un échec devient un manque déclaré, jamais une exception."""
    artefacts = _artefacts_for(axe, audit)
    artefacts, agregations = fit_to_budget(artefacts, budget_tokens)
    axe.agregations = agregations

    failures = axis_failures(axe, audit)
    system = build_system_prompt(audit, commands_meta)
    user = build_user_prompt(axe, audit, commands_meta, artefacts, failures)

    try:
        outcome = caller.complete(system, user, strict_schema(ResultatAxe))
    except Exception as exc:
        axe.erreur = f"appel du modèle impossible : {exc}"
        return axe

    if outcome.refusal is not None:
        axe.erreur = (
            f"refus du modèle ({outcome.refusal}) — axe non évalué. "
            "Les classificateurs de sécurité ont décliné la requête."
        )
        return axe
    if outcome.data is None:
        axe.erreur = "réponse vide du modèle — axe non évalué."
        return axe

    try:
        axe.resultat = ResultatAxe.model_validate(outcome.data)
    except Exception as exc:
        axe.erreur = f"réponse non conforme au schéma : {exc}"
        return axe

    axe.extraits_invérifiables = verify_excerpts(axe.resultat, audit)
    return axe
