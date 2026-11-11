"""
Unit tests for the rule store: validation, CRUD, built-in protection,
mtime-based hot reload, legacy-YAML tolerance and atomic writes.
"""

import os
import time

import pytest
import yaml

from scanner.rule_store import (
    RuleStore,
    RuleValidationError,
    BuiltinRuleError,
)
from tests.conftest import load_yaml_rules


# ------------------------------------------------------------- validation

def test_rules_accept_valid_payload(store, sample_rule_payload):
    rule = store.add_rule(sample_rule_payload)

    assert rule["id"].startswith("CUSTOM-")
    assert rule["source"] == "custom"
    assert rule["enabled"] is True
    assert rule["severity"] == "critical"  # normalized to lowercase
    assert rule["language"] == "python"


def test_rules_severity_is_case_insensitive(store, sample_rule_payload):
    sample_rule_payload["severity"] = "HIGH"
    rule = store.add_rule(sample_rule_payload)
    assert rule["severity"] == "high"


@pytest.mark.parametrize("bad_severity", ["urgent", "", "CRITICAL;", 5, None])
def test_rules_reject_unknown_severity(store, sample_rule_payload, bad_severity):
    sample_rule_payload["severity"] = bad_severity
    with pytest.raises(RuleValidationError) as exc:
        store.add_rule(sample_rule_payload)
    assert "severity" in str(exc.value)


def test_rules_reject_invalid_regex_with_reason(store, sample_rule_payload):
    sample_rule_payload["pattern"] = "(unclosed"
    with pytest.raises(RuleValidationError) as exc:
        store.add_rule(sample_rule_payload)
    assert "invalid regex pattern" in str(exc.value)


def test_rules_reject_missing_name_and_pattern(store):
    with pytest.raises(RuleValidationError) as exc:
        store.add_rule({"severity": "low"})
    message = str(exc.value)
    assert "'name'" in message
    assert "'pattern'" in message


def test_rules_reject_non_dict_payload(store):
    with pytest.raises(RuleValidationError):
        store.add_rule(["not", "a", "dict"])


def test_rules_reject_duplicate_id(store, sample_rule_payload):
    sample_rule_payload["id"] = "DUP-001"
    store.add_rule(sample_rule_payload)

    with pytest.raises(RuleValidationError) as exc:
        store.add_rule({**sample_rule_payload, "name": "Other"})
    assert "already exists" in str(exc.value)


# ------------------------------------------------------------------- CRUD

def test_rules_persist_to_yaml(store, rules_path, sample_rule_payload):
    rule = store.add_rule(sample_rule_payload)

    persisted = load_yaml_rules(rules_path)
    assert len(persisted) == 1
    assert persisted[0]["id"] == rule["id"]
    assert persisted[0]["pattern"] == sample_rule_payload["pattern"]


def test_rules_generated_ids_are_unique(store, sample_rule_payload):
    first = store.add_rule(sample_rule_payload)
    second = store.add_rule({**sample_rule_payload, "description": "again"})
    assert first["id"] != second["id"]


def test_rules_toggle_enabled(store, sample_rule_payload):
    rule = store.add_rule(sample_rule_payload)

    updated = store.set_enabled(rule["id"], False)
    assert updated["enabled"] is False
    assert store.find_rule(rule["id"])["enabled"] is False

    store.set_enabled(rule["id"], True)
    assert store.find_rule(rule["id"])["enabled"] is True


def test_rules_delete_custom(store, sample_rule_payload):
    rule = store.add_rule(sample_rule_payload)
    store.delete_rule(rule["id"])

    assert store.find_rule(rule["id"]) is None
    assert load_yaml_rules(store.rules_path) == []


def test_rules_delete_unknown_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.delete_rule("DOES-NOT-EXIST")


def test_rules_toggle_unknown_raises_keyerror(store):
    with pytest.raises(KeyError):
        store.set_enabled("DOES-NOT-EXIST", False)


# ------------------------------------------------------ built-in protection

def test_rules_builtin_listed_and_marked(store):
    builtin = store.get_builtin_rules()
    assert builtin, "expected built-in patterns to be exposed"
    assert all(r["source"] == "builtin" for r in builtin)
    assert all(r["id"].startswith("BUILTIN-") for r in builtin)


def test_rules_builtin_ids_are_stable_across_instances(rules_path):
    first = RuleStore(rules_path).get_builtin_rules()
    second = RuleStore(rules_path).get_builtin_rules()
    assert [r["id"] for r in first] == [r["id"] for r in second]


def test_rules_cannot_delete_builtin(store):
    builtin_id = store.get_builtin_rules()[0]["id"]
    with pytest.raises(BuiltinRuleError):
        store.delete_rule(builtin_id)


def test_rules_cannot_toggle_builtin(store):
    builtin_id = store.get_builtin_rules()[0]["id"]
    with pytest.raises(BuiltinRuleError):
        store.set_enabled(builtin_id, False)


# ------------------------------------------------------------- hot reload

def test_rules_reload_on_mtime_change(rules_path, sample_rule_payload):
    store = RuleStore(rules_path)
    store.add_rule(sample_rule_payload)

    # Simulate a second process/instance writing to the same file.
    other = RuleStore(rules_path)
    other.add_rule({**sample_rule_payload, "name": "second rule"})

    # Bump mtime so the first store's cache check detects the change.
    future = time.time() + 5
    os.utime(rules_path, (future, future))

    ids = {r["id"] for r in store.get_custom_rules()}
    assert len(ids) == 2


def test_rules_disabled_rules_excluded_from_scan_snapshot(store, sample_rule_payload):
    rule = store.add_rule(sample_rule_payload)
    store.set_enabled(rule["id"], False)

    assert store.get_enabled_custom_rules() == []
    assert len(store.get_custom_rules()) == 1


def test_rules_tolerate_legacy_ast_shaped_yaml(tmp_path):
    rules_path = str(tmp_path / "custom_rules.yaml")
    legacy = {
        "language": "python",
        "rules": [
            {  # legacy AST rule without a regex 'pattern' -> skipped
                "id": "PY-LEGACY-001",
                "name": "Legacy eval rule",
                "severity": "High",
                "patterns": [{"type": "function_call", "name": "eval"}],
            },
            {  # current regex rule -> kept
                "id": "PY-NEW-001",
                "name": "Regex rule",
                "pattern": r"eval\(",
                "severity": "high",
                "language": "python",
            },
        ],
    }
    os.makedirs(os.path.dirname(rules_path), exist_ok=True)
    with open(rules_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(legacy, fh)

    store = RuleStore(rules_path)
    loaded = store.get_custom_rules()
    assert [r["id"] for r in loaded] == ["PY-NEW-001"]


def test_rules_missing_file_loads_empty(tmp_path):
    store = RuleStore(str(tmp_path / "nope" / "custom_rules.yaml"))
    assert store.get_custom_rules() == []


# ----------------------------------------------------------- atomic writes

def test_rules_no_temp_files_left_behind(store, sample_rule_payload):
    for i in range(5):
        store.add_rule({**sample_rule_payload, "name": f"rule {i}"})

    directory = os.path.dirname(store.rules_path)
    leftovers = [f for f in os.listdir(directory) if f.endswith(".tmp")]
    assert leftovers == []


def test_rules_yaml_always_parseable_after_each_write(store, sample_rule_payload):
    for i in range(5):
        store.add_rule({**sample_rule_payload, "name": f"rule {i}"})
        # Every intermediate state must be a complete, valid document.
        rules = load_yaml_rules(store.rules_path)
        assert len(rules) == i + 1
