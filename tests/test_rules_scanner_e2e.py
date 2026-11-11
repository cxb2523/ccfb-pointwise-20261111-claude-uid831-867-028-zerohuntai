"""
End-to-end rule tests through LocalScanner.

Verifies that:
  * a real directory scan applies custom rules from the store,
  * each scan is bracketed by begin_scan/end_scan (snapshot released after),
  * a generated JSON report stays self-contained after the rule is deleted.
"""

import json
import os

import pytest

from scanner.local_scanner import LocalScanner
from scanner.rule_store import get_rule_store


@pytest.fixture
def project_dir(tmp_path):
    """A tiny Python project containing a marker that only the custom rule matches."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text(
        'DB_PASSWORD = "SECRET-MARKER-pw"\n'
        'def harmless():\n    return 42\n',
        encoding="utf-8",
    )
    return source


@pytest.fixture
def marker_rule(store):
    return store.add_rule({
        "id": "CUSTOM-E2E-001",
        "name": "E2E marker rule",
        "pattern": r"SECRET-MARKER",
        "severity": "critical",
        "language": "python",
        "description": "end-to-end marker",
    })


def _run_scanner(project_dir, tmp_path):
    output_dir = tmp_path / "output"
    scanner = LocalScanner(
        str(project_dir),
        output_dir=str(output_dir),
        verbose=False,
        scan_secrets=False,
        enable_call_graph=False,
    )
    result = scanner.scan()
    report_path = scanner.generate_report(format="json")
    return scanner, result, report_path


def test_rules_scanner_applies_custom_rule_and_snapshots_finding(
    project_dir, tmp_path, marker_rule
):
    scanner, result, report_path = _run_scanner(project_dir, tmp_path)

    custom = [v for v in result["vulnerabilities"] if v.get("source") == "custom"]
    assert len(custom) == 1
    finding = custom[0]
    assert finding["rule_id"] == "CUSTOM-E2E-001"
    assert finding["rule_name"] == "E2E marker rule"
    assert finding["severity"] == "Critical"

    # Critical findings are counted in the scan stats.
    assert result["stats"]["critical_severity"] >= 1
    assert result["stats"]["total_vulnerabilities"] == len(result["vulnerabilities"])

    # Snapshot lifecycle: released once the scan completes, so the next scan
    # will re-check the rule file's mtime instead of using stale rules.
    assert scanner.analyzer._scan_snapshot is None

    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    reported = [v for v in report["vulnerabilities"] if v.get("rule_id") == "CUSTOM-E2E-001"]
    assert len(reported) == 1
    assert reported[0]["rule_name"] == "E2E marker rule"
    assert reported[0]["severity"] == "Critical"


def test_rules_report_remains_complete_after_rule_deleted(
    project_dir, tmp_path, marker_rule
):
    _, _, report_path = _run_scanner(project_dir, tmp_path)

    # Operator retires the rule after the scan finished.
    get_rule_store().delete_rule(marker_rule["id"])
    assert get_rule_store().find_rule(marker_rule["id"]) is None

    # Historical report must still render every field without looking anything
    # up in the (now smaller) rule table.
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    historical = [v for v in report["vulnerabilities"] if v.get("rule_id") == "CUSTOM-E2E-001"]
    assert len(historical) == 1
    assert historical[0]["rule_id"] == "CUSTOM-E2E-001"
    assert historical[0]["rule_name"] == "E2E marker rule"
    assert historical[0]["severity"] == "Critical"
    assert historical[0]["description"] == "end-to-end marker"

    # And a fresh scan no longer reports the retired rule.
    _, second_result, _ = _run_scanner(project_dir, tmp_path / "second")
    assert not any(
        v.get("rule_id") == "CUSTOM-E2E-001"
        for v in second_result["vulnerabilities"]
    )


def test_rules_disabled_rule_skipped_by_full_scan(project_dir, tmp_path, marker_rule):
    get_rule_store().set_enabled(marker_rule["id"], False)

    _, result, _ = _run_scanner(project_dir, tmp_path / "output")
    assert not any(v.get("rule_id") == "CUSTOM-E2E-001" for v in result["vulnerabilities"])
