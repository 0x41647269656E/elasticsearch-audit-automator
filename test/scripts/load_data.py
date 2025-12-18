import gzip
import json
import logging
import os
import time
from typing import Iterable, List

import requests
from elasticsearch import Elasticsearch, helpers

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def env_list(name: str, default: str = "") -> List[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def build_client(host: str, username: str, password: str, verify: bool, ca_cert: str | None) -> Elasticsearch:
    kwargs = {
        "hosts": [host],
        "basic_auth": (username, password),
        "verify_certs": verify,
    }
    if ca_cert:
        kwargs["ca_certs"] = ca_cert
    return Elasticsearch(**kwargs)


def wait_for_green(client: Elasticsearch, timeout: int = 600) -> None:
    start = time.time()
    while True:
        try:
            health = client.cluster.health(request_timeout=60)
            status = health.get("status")
            logger.info("Cluster health: %s", status)
            if status == "green":
                return
        except Exception as exc:  # noqa: BLE001
            logger.warning("Health check failed: %s", exc)
        if time.time() - start > timeout:
            raise TimeoutError("Cluster did not reach green status in time")
        time.sleep(10)


def ensure_user(client: Elasticsearch, username: str, password: str) -> None:
    try:
        client.security.get_user(username=username)
        logger.info("User %s already exists", username)
        return
    except Exception:  # noqa: BLE001
        logger.info("Creating user %s", username)
    client.security.put_user(
        username=username,
        body={
            "password": password,
            "roles": ["superuser"],
            "full_name": "Audit automation",
            "email": "audit@example.com",
        },
    )


def create_indices(client: Elasticsearch, index_prefix: str, count: int) -> List[str]:
    names = [f"{index_prefix}-{i:02d}" for i in range(1, count + 1)]
    for name in names:
        try:
            client.indices.create(index=name, ignore=400, body={"settings": {"number_of_shards": 1, "number_of_replicas": 1}})
            logger.info("Ensured index %s exists", name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Index creation issue for %s: %s", name, exc)
    return names


def stream_dataset(url: str) -> Iterable[dict]:
    logger.info("Downloading dataset %s", url)
    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        raw_stream = resp.raw
        if url.endswith(".gz"):
            raw_stream = gzip.GzipFile(fileobj=resp.raw)
        for line in raw_stream:
            if not line:
                continue
            try:
                yield json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                continue


def generate_actions(urls: List[str], indices: List[str]) -> Iterable[dict]:
    index_count = len(indices)
    for url in urls:
        for idx, doc in enumerate(stream_dataset(url)):
            target_index = indices[idx % index_count]
            yield {
                "_index": target_index,
                "_source": doc,
            }


def bulk_ingest(
    client: Elasticsearch,
    urls: List[str],
    indices: List[str],
    batch_size: int = 500,
    request_timeout: int = 120,
) -> None:
    total = 0
    for ok, result in helpers.streaming_bulk(
        client,
        generate_actions(urls, indices),
        chunk_size=batch_size,
        request_timeout=request_timeout,
        max_retries=5,
        initial_backoff=2,
        max_backoff=30,
        raise_on_error=False,
    ):
        total += 1
        if not ok:
            logger.warning("Bulk item error: %s", result)
        if total % (batch_size * 5) == 0:
            logger.info("Indexed %s documents so far", total)
    logger.info("Ingestion finished; total items processed: %s", total)


def main() -> None:
    host = os.getenv("ELASTIC_HOST", "http://localhost:9200")
    username = os.getenv("ELASTIC_USERNAME", "elastic")
    password = os.getenv("ELASTIC_PASSWORD", "changeme")
    target_username = os.getenv("TARGET_USERNAME", "audit-elasticsearch")
    target_password = os.getenv("TARGET_PASSWORD", "audit-me")
    index_prefix = os.getenv("TARGET_INDEX_PREFIX", "audit-demo")
    index_count = int(os.getenv("INDEX_COUNT", "10"))
    verify_certs = os.getenv("VERIFY_CERTS", "false").lower() == "true"
    ca_cert = os.getenv("CA_CERT_PATH")
    bulk_chunk_size = int(os.getenv("BULK_CHUNK_SIZE", "500"))
    bulk_request_timeout = int(os.getenv("BULK_REQUEST_TIMEOUT", "120"))

    dataset_urls = env_list(
        "DATASET_URLS",
        default="https://data.gharchive.org/2024-01-01-0.json.gz,https://data.gharchive.org/2024-01-01-1.json.gz",
    )

    admin_client = build_client(host, username, password, verify_certs, ca_cert)
    wait_for_green(admin_client)

    ensure_user(admin_client, target_username, target_password)

    user_client = build_client(host, target_username, target_password, verify_certs, ca_cert)
    indices = create_indices(user_client, index_prefix, index_count)
    bulk_ingest(user_client, dataset_urls, indices, batch_size=bulk_chunk_size, request_timeout=bulk_request_timeout)

    logger.info("Data load complete for indices: %s", ", ".join(indices))


if __name__ == "__main__":
    main()
