"""
Tests for per-scan rule snapshots and self-contained finding metadata.

A running scan must keep using the rule set it started with even when rules
are added/toggled/deleted mid-scan, and findings must snapshot rule_id,
rule_name and severity so historical reports never look the rule table back up.
"""

import pytest

from scanner.analyzer import CodeAnalyzer
from tests.conftest import load_yaml_rules


SAMPLE_CODE = """
api_token = "SECRET-MARKER-abc123"
"""


def _custom_findings(analyzer, code=SAMPLE_CODE):
    result = analyzer.analyze_code(code, ".py", "sample.py")
    return [v for v in result["vulnerabilities"] if v.get("source") == "custom"]


@pytest.fixture
def analyzer(store):
    return CodeAnalyzer()


@pytest.fixture
def marker_rule(store):
    return store.add_rule({
        "id": "CUSTOM-MARKER-001",
        "name": "Marker secret rule",
        "pattern": r"SECRET-MARKER",
        "severity": "high",
        "language": "python",
        "description": "flags the test marker",
    })


def test_rules_finding_carries_snapshotted_metadata(analyzer, marker_rule):
    analyzer.begin_scan()
    try:
        findings = _custom_findings(analyzer)
    finally:
        analyzer.end_scan()

    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "CUSTOM-MARKER-001"
    assert finding["rule_name"] == "Marker secret rule"
    assert finding["severity"] == "High"  # display form, snapshotted


def test_rules_configured_severity_is_not_overwritten_by_ai_scorer(analyzer, store):
    store.add_rule({
        "id": "CUSTOM-CRIT-001",
        "name": "Critical marker",
        "pattern": r"SECRET-MARKER",
        "severity": "critical",
        "language": "python",
    })
    analyzer.begin_scan()
    try:
        finding = _custom_findings(analyzer)[0]
    finally:
        analyzer.end_scan()

    # The AI scorer only emits Low/Medium/High; Critical proves it was bypassed.
    assert finding["severity"] == "Critical"


def test_rules_running_scan_keeps_snapshot_when_rule_disabled(analyzer, store, marker_rule):
    analyzer.begin_scan()
    try:
        assert len(_custom_findings(analyzer)) == 1

        # Operator disables the rule while the scan is in flight.
        store.set_enabled(marker_rule["id"], False)

        # The pinned snapshot still contains the rule: no mid-scan caliber change.
        findings = _custom_findings(analyzer)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == marker_rule["id"]
    finally:
        analyzer.end_scan()

    # The next scan picks up the new rule version (rule now disabled).
    analyzer.begin_scan()
    try:
        assert _custom_findings(analyzer) == []
    finally:
        analyzer.end_scan()


def test_rules_running_scan_keeps_snapshot_when_rule_deleted(analyzer, store, marker_rule):
    analyzer.begin_scan()
    try:
        findings_before = _custom_findings(analyzer)
        assert len(findings_before) == 1

        store.delete_rule(marker_rule["id"])

        # In-flight scan still evaluates against its startup snapshot.
        findings_during = _custom_findings(analyzer)
        assert len(findings_during) == 1

        # And the historical finding remains fully self-contained after the
        # rule is gone — reports never query the rule table again.
        historical = findings_before[0]
        assert historical["rule_id"] == marker_rule["id"]
        assert historical["rule_name"] == "Marker secret rule"
        assert historical["severity"] == "High"
    finally:
        analyzer.end_scan()

    # Fresh scan after deletion: nothing to match anymore.
    analyzer.begin_scan()
    try:
        assert _custom_findings(analyzer) == []
    finally:
        analyzer.end_scan()


def test_rules_new_rule_added_mid_scan_does_not_leak_into_running_scan(analyzer, store, marker_rule):
    analyzer.begin_scan()
    try:
        store.add_rule({
            "id": "CUSTOM-LATE-001",
            "name": "Late arriving rule",
            "pattern": r"LATE-MARKER",
            "severity": "low",
            "language": "python",
        })
        result = analyzer.analyze_code(
            "x = 'LATE-MARKER'\n", ".py", "late.py"
        )
        custom = [v for v in result["vulnerabilities"] if v.get("rule_id") == "CUSTOM-LATE-001"]
        assert custom == []  # snapshot was taken before the rule existed
    finally:
        analyzer.end_scan()

    analyzer.begin_scan()
    try:
        result = analyzer.analyze_code("x = 'LATE-MARKER'\n", ".py", "late.py")
        assert any(v.get("rule_id") == "CUSTOM-LATE-001" for v in result["vulnerabilities"])
    finally:
        analyzer.end_scan()


def test_rules_disabled_rule_never_matches(analyzer, store, marker_rule):
    store.set_enabled(marker_rule["id"], False)
    analyzer.begin_scan()
    try:
        assert _custom_findings(analyzer) == []
    finally:
        analyzer.end_scan()


def test_rules_generic_language_rule_matches_python_files(analyzer, store):
    store.add_rule({
        "id": "CUSTOM-GEN-001",
        "name": "Generic marker",
        "pattern": r"SECRET-MARKER",
        "severity": "medium",
        "language": "generic",
    })
    analyzer.begin_scan()
    try:
        findings = _custom_findings(analyzer)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CUSTOM-GEN-001"
    finally:
        analyzer.end_scan()


def test_rules_language_mismatch_does_not_match(analyzer, store):
    store.add_rule({
        "id": "CUSTOM-JS-001",
        "name": "JS only rule",
        "pattern": r"SECRET-MARKER",
        "severity": "low",
        "language": "javascript",
    })
    analyzer.begin_scan()
    try:
        assert _custom_findings(analyzer) == []
        js_result = analyzer.analyze_code(SAMPLE_CODE, ".js", "sample.js")
        assert any(v.get("rule_id") == "CUSTOM-JS-001" for v in js_result["vulnerabilities"])
    finally:
        analyzer.end_scan()


def test_rules_builtin_findings_also_carry_rule_identity(analyzer):
    analyzer.begin_scan()
    try:
        # eval( matches a built-in python pattern.
        result = analyzer.analyze_code("x = eval(user_input)\n", ".py", "eval.py")
    finally:
        analyzer.end_scan()

    builtin = [v for v in result["vulnerabilities"] if v.get("source") == "builtin"]
    assert builtin
    assert all(v["rule_id"].startswith("BUILTIN-") for v in builtin)
    assert all(v["rule_name"] for v in builtin)
