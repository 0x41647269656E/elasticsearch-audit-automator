"""Lecture d'un dossier d'audit produit par main.py.

Deux générations de dossiers coexistent : ceux collectés avant l'ajout des
métadonnées par commande, et les autres. Les premiers restent analysables — le
rapport se rabat alors sur l'horodatage global et le signale.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

INFOS = "audit_infos.json"
ERROR_SUFFIX = "-error"
SIDECAR_SUFFIX = ".meta.json"


@dataclass
class Artefact:
    """Une sortie de commande et les conditions dans lesquelles elle a été prise."""

    name: str
    data: Any
    metadata: Dict[str, Any]
    output_format: str
    path: Path

    @property
    def size(self) -> int:
        return self.path.stat().st_size


@dataclass
class Audit:
    directory: Path
    infos: Dict[str, Any]
    artefacts: Dict[str, Artefact] = field(default_factory=dict)
    failures: Dict[str, str] = field(default_factory=dict)
    has_metadata: bool = False

    @property
    def cluster_name(self) -> Optional[str]:
        return self.infos.get("cluster_name")

    @property
    def typology(self) -> Optional[str]:
        return self.infos.get("cluster_typology")

    @property
    def node_name(self) -> Optional[str]:
        return self.infos.get("node_name")

    @property
    def timestamp(self) -> Optional[str]:
        return self.infos.get("timestamp")


def _fallback_metadata(infos: Dict[str, Any], command: Optional[str] = None) -> Dict[str, Any]:
    """Métadonnées d'un dossier antérieur : horodatage global, nœud inconnu."""
    return {
        "node": infos.get("node_name"),
        "at": infos.get("timestamp"),
        "command": command,
        "status": None,
        "duration_ms": None,
        "_degraded": True,
    }


def load_audit(directory: Path | str) -> Audit:
    directory = Path(directory)
    infos_path = directory / INFOS
    infos = json.loads(infos_path.read_text(encoding="utf-8")) if infos_path.exists() else {}
    audit = Audit(directory=directory, infos=infos)

    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == INFOS or path.name.endswith(SIDECAR_SUFFIX):
            continue
        if path.suffix not in {".json", ".txt"}:
            continue

        stem = path.stem
        if stem.endswith(ERROR_SUFFIX):
            audit.failures[stem[: -len(ERROR_SUFFIX)]] = path.read_text(encoding="utf-8")
            continue

        if path.suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and "_audit" in payload and "_data" in payload:
                data, metadata = payload["_data"], payload["_audit"]
                audit.has_metadata = True
            else:
                data, metadata = payload, _fallback_metadata(infos)
            output_format = "json"
        else:
            data = path.read_text(encoding="utf-8")
            sidecar = directory / f"{stem}{SIDECAR_SUFFIX}"
            if sidecar.exists():
                metadata = json.loads(sidecar.read_text(encoding="utf-8"))
                audit.has_metadata = True
            else:
                metadata = _fallback_metadata(infos)
            output_format = "text"

        audit.artefacts[stem] = Artefact(stem, data, metadata, output_format, path)

    return audit
