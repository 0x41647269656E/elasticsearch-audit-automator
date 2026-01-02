import json
import logging
import os
import random
import time
from typing import Any, Dict, List

from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def build_client(host: str, username: str, password: str, verify: bool, ca_cert: str | None) -> Elasticsearch:
    kwargs: Dict[str, Any] = {"hosts": [host], "verify_certs": verify}
    if username and password:
        kwargs["basic_auth"] = (username, password)
    if ca_cert:
        kwargs["ca_certs"] = ca_cert
    return Elasticsearch(**kwargs)


def load_seed(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def ensure_activity_index(client: Elasticsearch, name: str) -> None:
    body = {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic": True,
            "date_detection": False,
        },
    }
    try:
        client.indices.create(index=name, body=body, ignore=400)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Index creation issue for %s: %s", name, exc)


def random_search(client: Elasticsearch, base_index: str, seeds: List[Dict[str, Any]]) -> None:
    if not seeds:
        return
    doc = random.choice(seeds)
    must = []
    if "event" in doc:
        must.append({"term": {"event.keyword": doc["event"]}})
    if "repo" in doc:
        must.append({"term": {"repo.keyword": doc["repo"]}})
    query = {"query": {"bool": {"must": must}}} if must else {"query": {"match_all": {}}}
    client.search(index=f"{base_index}-*", body=query, size=5, request_timeout=30)


def random_ingest(client: Elasticsearch, activity_index: str, worker_id: str, seeds: List[Dict[str, Any]]) -> None:
    base = random.choice(seeds) if seeds else {}
    doc = {
        "worker": worker_id,
        "ts": time.time(),
        "note": "synthetic activity",
        "seed_event": base.get("event"),
        "seed_repo": base.get("repo"),
    }
    client.index(index=activity_index, document=doc, request_timeout=30)


def main() -> None:
    host = os.getenv("ELASTIC_HOST", "http://localhost:9200")
    username = os.getenv("ELASTIC_USERNAME", "elastic")
    password = os.getenv("ELASTIC_PASSWORD", "changeme")
    verify_certs = os.getenv("VERIFY_CERTS", "false").lower() == "true"
    ca_cert = os.getenv("CA_CERT_PATH")
    seed_file = os.getenv("DATA_FILE", "/app/dummy_data.json")
    base_index = os.getenv("TARGET_INDEX_PREFIX", "audit-demo")
    operations = int(os.getenv("WORKER_OPS", "50"))
    pause = float(os.getenv("WORKER_PAUSE", "0.2"))
    worker_id = os.getenv("WORKER_ID", "worker-1")
    activity_index = os.getenv("ACTIVITY_INDEX", "audit-activity")

    client = build_client(host, username, password, verify_certs, ca_cert)
    # sseeds = load_seed(seed_file)
    ensure_activity_index(client, activity_index)

    for i in range(operations):
        try:
            random_search(client, base_index, seeds)
            random_ingest(client, activity_index, worker_id, seeds)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Worker error on op %s: %s", i, exc)
        time.sleep(pause)

    logger.info("Worker %s completed %s operations", worker_id, operations)


if __name__ == "__main__":
    main()
