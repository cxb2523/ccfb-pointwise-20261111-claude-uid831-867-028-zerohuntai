"""
HTTP-level tests for the rule management API in app.py:
POST / GET / PATCH / DELETE /api/rules, including validation and
built-in rule protection.
"""

from tests.conftest import load_yaml_rules


def test_rules_api_list_includes_source(client, store):
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == len(body["rules"])
    sources = {r["source"] for r in body["rules"]}
    assert sources == {"builtin"}  # no custom rules yet


def test_rules_api_create(client, rules_path, sample_rule_payload):
    resp = client.post("/api/rules", json=sample_rule_payload)
    assert resp.status_code == 201
    rule = resp.get_json()
    assert rule["id"]
    assert rule["source"] == "custom"
    assert rule["severity"] == "critical"

    persisted = load_yaml_rules(rules_path)
    assert persisted[0]["id"] == rule["id"]

    # It now shows up in the listing.
    listing = client.get("/api/rules").get_json()
    ids = {r["id"] for r in listing["rules"]}
    assert rule["id"] in ids


def test_rules_api_create_invalid_regex_returns_400(client, sample_rule_payload):
    sample_rule_payload["pattern"] = "([0-9"
    resp = client.post("/api/rules", json=sample_rule_payload)
    assert resp.status_code == 400
    assert "regex" in resp.get_json()["error"]


def test_rules_api_create_invalid_severity_returns_400(client, sample_rule_payload):
    sample_rule_payload["severity"] = "catastrophic"
    resp = client.post("/api/rules", json=sample_rule_payload)
    assert resp.status_code == 400
    assert "severity" in resp.get_json()["error"]


def test_rules_api_create_rejects_non_json_body(client):
    resp = client.post("/api/rules", data="not json", content_type="text/plain")
    assert resp.status_code == 400
    assert "JSON" in resp.get_json()["error"]


def test_rules_api_patch_toggles_enabled(client, sample_rule_payload):
    rule_id = client.post("/api/rules", json=sample_rule_payload).get_json()["id"]

    resp = client.patch(f"/api/rules/{rule_id}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is False

    resp = client.patch(f"/api/rules/{rule_id}", json={"enabled": True})
    assert resp.get_json()["enabled"] is True


def test_rules_api_patch_rejects_non_boolean(client, sample_rule_payload):
    rule_id = client.post("/api/rules", json=sample_rule_payload).get_json()["id"]
    resp = client.patch(f"/api/rules/{rule_id}", json={"enabled": "yes"})
    assert resp.status_code == 400


def test_rules_api_patch_unknown_id_returns_404(client):
    resp = client.patch("/api/rules/NO-SUCH-RULE", json={"enabled": False})
    assert resp.status_code == 404


def test_rules_api_patch_builtin_returns_403(client, store):
    builtin_id = store.get_builtin_rules()[0]["id"]
    resp = client.patch(f"/api/rules/{builtin_id}", json={"enabled": False})
    assert resp.status_code == 403
    assert "built-in" in resp.get_json()["error"]


def test_rules_api_delete_custom(client, sample_rule_payload):
    rule_id = client.post("/api/rules", json=sample_rule_payload).get_json()["id"]

    resp = client.delete(f"/api/rules/{rule_id}")
    assert resp.status_code == 200
    assert resp.get_json()["deleted"] is True

    assert client.delete(f"/api/rules/{rule_id}").status_code == 404


def test_rules_api_delete_builtin_returns_403(client, store):
    builtin_id = store.get_builtin_rules()[0]["id"]
    resp = client.delete(f"/api/rules/{builtin_id}")
    assert resp.status_code == 403
    assert "built-in" in resp.get_json()["error"]


def test_rules_api_delete_unknown_returns_404(client):
    resp = client.delete("/api/rules/NO-SUCH-RULE")
    assert resp.status_code == 404
