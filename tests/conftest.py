"""
Shared fixtures for rule-management tests.

Each test gets an isolated rules directory plus a reset rule-store singleton,
so the real rules/custom_rules.yaml is never touched by the test suite.
"""

import os
import sys

import pytest

# Make the project root importable regardless of the pytest invocation dir.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import yaml  # noqa: E402

from scanner import rule_store as rule_store_module  # noqa: E402
from scanner.rule_store import RuleStore  # noqa: E402


@pytest.fixture
def rules_path(tmp_path):
    """Path to a fresh, empty custom-rules YAML file."""
    return str(tmp_path / "rules" / "custom_rules.yaml")


@pytest.fixture
def store(rules_path):
    """A RuleStore backed by a temp file, installed as the process singleton."""
    test_store = RuleStore(rules_path)
    rule_store_module._store = test_store
    yield test_store
    rule_store_module._store = None


@pytest.fixture
def flask_app(store):
    """The Flask app configured for testing, backed by the temp rule store."""
    from app import app

    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(flask_app):
    """Flask test client for single-threaded request tests."""
    with flask_app.test_client() as test_client:
        yield test_client


@pytest.fixture
def sample_rule_payload():
    return {
        "name": "Detect hardcoded token",
        "pattern": r"token\s*=\s*[\"'][^\"']+[\"']",
        "severity": "critical",
        "language": "python",
        "description": "Hardcoded token assignment",
    }


def load_yaml_rules(path):
    """Helper: parse the YAML file straight from disk."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict) and isinstance(data.get("rules"), list)
    return data["rules"]
