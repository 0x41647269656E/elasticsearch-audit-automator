"""Agrégations ciblées pour tenir dans la fenêtre de contexte.

Sur un cluster client, les artefacts d'un seul axe dépassent le million de
jetons : mesuré sur un cluster réel puis extrapolé à 400 index, cinq axes sur
dix débordent. Trois artefacts en sont responsables, et pour chacun l'audit
n'a pas besoin de l'énumération complète — il a besoin des chiffres que le
prompt de la commande réclame déjà.

Ce ne sont donc pas des troncatures : `summarise_segments` répond exactement à
« le nombre de segments par shard, leur taille », en dense.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Tuple

# Types dont la présence pèse sur la mémoire ou la performance de recherche.
COSTLY_TYPES = {"nested", "join", "dense_vector", "sparse_vector", "flattened"}

# Estimation locale, utilisée quand aucun compteur de jetons n'est fourni.
# Le JSON dense tokenise autour de 3,5 octets par jeton.
BYTES_PER_TOKEN = 3.5


def encoded_size(payload: Any) -> int:
    """Taille du JSON compact, en octets."""
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


def estimate_tokens(payload: Any) -> int:
    return int(encoded_size(payload) / BYTES_PER_TOKEN)


def summarise_segments(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Remplace l'énumération des segments par leurs agrégats, shard par shard."""
    indices: Dict[str, Any] = {}
    for index_name, index_body in payload.get("indices", {}).items():
        shards: Dict[str, Any] = {}
        for shard_id, copies in index_body.get("shards", {}).items():
            resumes = []
            for copy in copies:
                segments = copy.get("segments", {}) or {}
                sizes = [s.get("size_in_bytes", 0) for s in segments.values()]
                resumes.append(
                    {
                        "routing": copy.get("routing"),
                        "segment_count": len(segments),
                        "size_in_bytes_total": sum(sizes),
                        "size_in_bytes_max": max(sizes, default=0),
                        "size_in_bytes_min": min(sizes, default=0),
                        "num_docs_total": sum(s.get("num_docs", 0) for s in segments.values()),
                        "deleted_docs_total": sum(
                            s.get("deleted_docs", 0) for s in segments.values()
                        ),
                    }
                )
            shards[shard_id] = resumes
        indices[index_name] = {"shards": shards}
    return {"_agrege": "segments résumés par shard", "indices": indices}


def _walk_fields(properties: Dict[str, Any], prefix: str = "") -> List[Tuple[str, Dict[str, Any]]]:
    """Aplatit un bloc de propriétés en (chemin pointé, définition)."""
    found: List[Tuple[str, Dict[str, Any]]] = []
    for name, definition in (properties or {}).items():
        path = f"{prefix}{name}"
        if isinstance(definition, dict):
            if "type" in definition or "properties" not in definition:
                found.append((path, definition))
            found.extend(_walk_fields(definition.get("properties", {}), f"{path}."))
    return found


def summarise_mappings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Remplace les mappings par leur forme : compte, types, champs à risque."""
    summary: Dict[str, Any] = {}
    for index_name, body in payload.items():
        mappings = body.get("mappings", {}) if isinstance(body, dict) else {}
        fields = _walk_fields(mappings.get("properties", {}))

        types: Dict[str, int] = {}
        costly: List[str] = []
        text_without_keyword: List[str] = []
        for path, definition in fields:
            field_type = definition.get("type")
            if not field_type:
                continue
            types[field_type] = types.get(field_type, 0) + 1
            if field_type in COSTLY_TYPES:
                costly.append(path)
            if field_type == "text":
                subfields = definition.get("fields", {}) or {}
                if not any(f.get("type") == "keyword" for f in subfields.values()):
                    text_without_keyword.append(path)

        summary[index_name] = {
            "field_count": len(fields),
            "types": types,
            "dynamic": mappings.get("dynamic"),
            "date_detection": mappings.get("date_detection"),
            "costly_fields": costly,
            "text_without_keyword": text_without_keyword,
        }
    return {"_agrege": "mappings résumés par index", **summary}


def summarise_cluster_state(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Garde le routage anormal et les métadonnées, sans redupliquer les mappings.

    Les mappings figurent déjà dans `indices_mappings` ; les répéter ici double
    l'artefact le plus lourd du cluster pour rien.
    """
    unassigned = []
    for index_name, index_body in payload.get("routing_table", {}).get("indices", {}).items():
        for shard_id, copies in index_body.get("shards", {}).items():
            for copy in copies:
                if copy.get("state") != "STARTED":
                    unassigned.append(
                        {
                            "index": index_name,
                            "shard": shard_id,
                            "primary": copy.get("primary"),
                            "state": copy.get("state"),
                            "reason": (copy.get("unassigned_info") or {}).get("reason"),
                            "details": (copy.get("unassigned_info") or {}).get("details"),
                        }
                    )

    metadata_indices = {
        name: {k: v for k, v in body.items() if k != "mappings"}
        for name, body in payload.get("metadata", {}).get("indices", {}).items()
    }

    return {
        "_agrege": "état du cluster résumé, mappings retirés (voir indices_mappings)",
        "cluster_name": payload.get("cluster_name"),
        "master_node": payload.get("master_node"),
        "blocks": payload.get("blocks", {}),
        "unassigned": unassigned,
        "metadata_indices": metadata_indices,
    }


REDUCERS: Dict[str, Callable[[Any], Any]] = {
    "indices_segments": summarise_segments,
    "indices_mappings": summarise_mappings,
    "cluster_state": summarise_cluster_state,
}


def fit_to_budget(
    artefacts: Dict[str, Any],
    budget_tokens: int,
    count_tokens: Callable[[Any], int] = estimate_tokens,
) -> Tuple[Dict[str, Any], List[str]]:
    """Agrège juste ce qu'il faut pour repasser sous le budget.

    Les artefacts sont réduits du plus lourd au plus léger, et l'opération
    s'arrête dès que l'axe tient. Retourne les artefacts et la liste de ceux
    qui ont été agrégés, pour que le rapport puisse le déclarer.
    """
    reduced = dict(artefacts)
    applied: List[str] = []

    if count_tokens(reduced) <= budget_tokens:
        return reduced, applied

    reducibles = sorted(
        (name for name in reduced if name in REDUCERS),
        key=lambda name: encoded_size(reduced[name]),
        reverse=True,
    )
    for name in reducibles:
        reduced[name] = REDUCERS[name](reduced[name])
        applied.append(name)
        if count_tokens(reduced) <= budget_tokens:
            break

    return reduced, applied
