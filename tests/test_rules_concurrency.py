"""
Concurrency tests for rule writes.

Twenty threads hammering the create-rule API at once must leave behind a
single, valid YAML document containing every rule — no torn writes, no
duplicate/lost updates. Also covers a mixed create/toggle/delete workload.

Each worker thread builds its own Flask test client: request/app contexts are
context-var scoped and cannot be shared across threads, mirroring how a real
multi-threaded WSGI server gives each request its own context.
"""

import concurrent.futures

from tests.conftest import load_yaml_rules


def _post_unique_rule(client, index):
    resp = client.post("/api/rules", json={
        "id": f"CONCURRENT-RULE-{index:03d}",
        "name": f"Concurrent rule {index}",
        "pattern": rf"MARKER_{index:03d}\s*=",
        "severity": ["critical", "high", "medium", "low"][index % 4],
        "language": "python",
        "description": f"rule created by worker {index}",
    })
    return resp.status_code


def test_rules_twenty_concurrent_creates_keep_yaml_intact(flask_app, rules_path):
    worker_count = 20

    def worker(index):
        with flask_app.test_client() as client:
            return _post_unique_rule(client, index)

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
        statuses = list(pool.map(worker, range(worker_count)))

    # Every request succeeded.
    assert statuses == [201] * worker_count

    # The on-disk YAML is one valid document with exactly all 20 rules.
    persisted = load_yaml_rules(rules_path)
    assert len(persisted) == worker_count
    ids = [r["id"] for r in persisted]
    assert len(set(ids)) == worker_count
    assert sorted(ids) == sorted(f"CONCURRENT-RULE-{i:03d}" for i in range(worker_count))

    # The store's cache agrees with disk and every rule is independently
    # retrievable.
    from scanner.rule_store import get_rule_store
    store = get_rule_store()
    for i in range(worker_count):
        rule = store.find_rule(f"CONCURRENT-RULE-{i:03d}")
        assert rule is not None and rule["source"] == "custom"


def test_rules_mixed_concurrent_operations_do_not_corrupt_yaml(
    flask_app, rules_path, sample_rule_payload
):
    # Seed ten rules first, on a single-threaded client.
    with flask_app.test_client() as client:
        for i in range(10):
            assert _post_unique_rule(client, i) == 201

    def worker(index):
        with flask_app.test_client() as client:
            if index % 3 == 0:
                return client.patch(
                    f"/api/rules/CONCURRENT-RULE-{index:03d}",
                    json={"enabled": False},
                ).status_code
            if index % 3 == 1:
                return client.delete(
                    f"/api/rules/CONCURRENT-RULE-{index:03d}"
                ).status_code
            # index % 3 == 2: create an extra rule
            return client.post("/api/rules", json={
                **sample_rule_payload,
                "id": f"CONCURRENT-EXTRA-{index:03d}",
                "name": f"extra {index}",
                "pattern": rf"EXTRA_{index:03d}",
            }).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(worker, range(10)))

    # All mutations are well-formed HTTP responses (no 500s).
    assert all(status in (200, 201) for status in statuses), statuses

    # The decisive check: YAML still parses as one coherent document.
    persisted = load_yaml_rules(rules_path)
    assert isinstance(persisted, list)
    assert len({r["id"] for r in persisted}) == len(persisted)


def test_rules_concurrent_creates_with_duplicate_id_serialize(flask_app):
    """Only one of 20 racing same-id inserts may win; the rest get 400."""
    def worker(_):
        with flask_app.test_client() as client:
            return client.post("/api/rules", json={
                "id": "RACING-SAME-ID",
                "name": "same id race",
                "pattern": r"RACE",
                "severity": "low",
                "language": "python",
            }).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        statuses = list(pool.map(worker, range(20)))

    assert statuses.count(201) == 1
    assert statuses.count(400) == 19

    from scanner.rule_store import get_rule_store
    persisted = load_yaml_rules(get_rule_store().rules_path)
    assert len(persisted) == 1
    assert persisted[0]["id"] == "RACING-SAME-ID"
