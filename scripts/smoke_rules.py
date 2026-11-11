"""
Live acceptance smoke test for the rule-management feature.

Spins up the real Flask app (threaded WSGI server, ephemeral port) against an
isolated rules file and verifies end-to-end:

  1. Twenty concurrent POST /api/rules requests all succeed and the YAML on
     disk remains one valid, complete document.
  2. A full LocalScanner scan keeps its startup rule snapshot when rules are
     deleted/toggled/created mid-scan (no mixed rule versions in one report),
     and every finding carries self-contained rule_id/rule_name/severity.
  3. A second scan after the churn picks up the new rule state.

Run:  python scripts/smoke_rules.py
Exit code 0 means acceptance passed.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

# Isolate ALL rule-file state before the app/store are imported.
TMP_ROOT = tempfile.mkdtemp(prefix="zerohuntai_smoke_")
RULES_DIR = os.path.join(TMP_ROOT, "rules")
os.makedirs(RULES_DIR, exist_ok=True)
os.environ["ZEROHUNTAI_RULES_PATH"] = os.path.join(RULES_DIR, "custom_rules.yaml")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import yaml  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

import app as app_module  # noqa: E402
from scanner.local_scanner import LocalScanner  # noqa: E402

RULES_PATH = os.environ["ZEROHUNTAI_RULES_PATH"]


def http_json(method, url, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(condition, message):
    if not condition:
        print(f"FAIL: {message}")
        sys.exit(1)
    print(f"ok: {message}")


def main():
    # ------------------------------------------------------------ boot server
    server = make_server("127.0.0.1", 0, app_module.app, threaded=True)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base = f"http://127.0.0.1:{port}"
    print(f"Flask server listening on {base}")

    try:
        # ------------------------------------------ 1. twenty concurrent creates
        def create_one(index):
            return http_json("POST", f"{base}/api/rules", {
                "id": f"SMOKE-RULE-{index:03d}",
                "name": f"Smoke rule {index}",
                "pattern": rf"SMOKE_MARKER_{index:03d}\s*=",
                "severity": ["critical", "high", "medium", "low"][index % 4],
                "language": "python",
                "description": f"concurrent create #{index}",
            })[0]

        with ThreadPoolExecutor(max_workers=20) as pool:
            statuses = list(pool.map(create_one, range(20)))

        check(statuses == [201] * 20, "all 20 concurrent create requests returned 201")

        with open(RULES_PATH, "r", encoding="utf-8") as fh:
            on_disk = yaml.safe_load(fh)
        persisted = on_disk["rules"]
        check(len(persisted) == 20, "YAML contains exactly 20 rules after concurrent writes")
        check(len({r["id"] for r in persisted}) == 20, "no duplicate rule ids in YAML")
        check(
            sorted(r["id"] for r in persisted)
            == sorted(f"SMOKE-RULE-{i:03d}" for i in range(20)),
            "every concurrent rule is persisted (no lost updates)",
        )
        check(
            not any(f.endswith(".tmp") for f in os.listdir(RULES_DIR)),
            "no leftover temp files next to the YAML",
        )

        # ------------------------------------------ 2. scan vs. concurrent churn
        project_dir = os.path.join(TMP_ROOT, "project")
        os.makedirs(project_dir, exist_ok=True)
        for i in range(100):
            with open(os.path.join(project_dir, f"mod_{i:03d}.py"), "w",
                      encoding="utf-8") as fh:
                fh.write('SMOKE_SNAPSHOT_MARKER = "value"\n')

        status, rule_r1 = http_json("POST", f"{base}/api/rules", {
            "id": "SMOKE-SNAPSHOT-001",
            "name": "Snapshot marker rule",
            "pattern": r"SMOKE_SNAPSHOT_MARKER",
            "severity": "critical",
            "language": "python",
        })
        check(status == 201, "created the rule the scan will snapshot")

        output_dir = os.path.join(TMP_ROOT, "output1")
        scanner = LocalScanner(
            project_dir, output_dir=output_dir,
            verbose=False, scan_secrets=False, enable_call_graph=False,
        )

        snapshot_ready = threading.Event()
        original_begin = scanner.analyzer.begin_scan

        def begin_with_signal():
            snapshot = original_begin()
            snapshot_ready.set()
            return snapshot

        scanner.analyzer.begin_scan = begin_with_signal

        scan_result_holder = {}

        def run_scan():
            scan_result_holder["result"] = scanner.scan()
            scan_result_holder["report"] = scanner.generate_report(format="json")

        scan_thread = threading.Thread(target=run_scan)
        scan_thread.start()
        check(snapshot_ready.wait(timeout=10), "scan pinned its rule snapshot")

        # Churn the rule table HARD while the scan is in flight, over HTTP.
        def churn():
            round_ = 0
            while scan_thread.is_alive():
                round_ += 1
                # The running snapshot must survive deletion of its rule.
                http_json("DELETE", f"{base}/api/rules/SMOKE-SNAPSHOT-001")
                http_json("POST", f"{base}/api/rules", {
                    "id": f"SMOKE-CHURN-{round_:03d}",
                    "name": f"churn {round_}",
                    "pattern": rf"CHURN_{round_}",
                    "severity": "low",
                    "language": "python",
                })
                http_json("PATCH", f"{base}/api/rules/SMOKE-RULE-000",
                          {"enabled": False})
                http_json("PATCH", f"{base}/api/rules/SMOKE-RULE-000",
                          {"enabled": True})

        churn_thread = threading.Thread(target=churn)
        churn_thread.start()
        scan_thread.join(timeout=60)
        churn_thread.join(timeout=10)
        check(not scan_thread.is_alive(), "first scan finished while rule churn ran")

        # YAML must still be intact after the storm.
        with open(RULES_PATH, "r", encoding="utf-8") as fh:
            after_churn = yaml.safe_load(fh)["rules"]
        check(isinstance(after_churn, list) and after_churn,
              "YAML remains a valid non-empty document after churn")

        result = scan_result_holder["result"]
        r1_findings = [
            v for v in result["vulnerabilities"]
            if v.get("rule_id") == "SMOKE-SNAPSHOT-001"
        ]
        check(len(r1_findings) == 100,
              "running scan used its startup snapshot: deleted rule still "
              "produced all 100 findings")
        check(
            all(v.get("rule_name") == "Snapshot marker rule"
                and v.get("severity") == "Critical"
                for v in r1_findings),
            "each finding self-contains snapshotted rule_name and severity",
        )
        churn_findings = [
            v for v in result["vulnerabilities"]
            if str(v.get("rule_id", "")).startswith("SMOKE-CHURN-")
        ]
        check(not churn_findings,
              "rules created mid-scan did not leak into the running scan")

        with open(scan_result_holder["report"], "r", encoding="utf-8") as fh:
            report = json.load(fh)
        check(
            len([v for v in report["vulnerabilities"]
                 if v.get("rule_id") == "SMOKE-SNAPSHOT-001"]) == 100,
            "historical JSON report stays complete after the rule was deleted",
        )

        # ------------------------------------------ 3. next scan uses new state
        scanner2 = LocalScanner(
            project_dir,
            output_dir=os.path.join(TMP_ROOT, "output2"),
            verbose=False, scan_secrets=False, enable_call_graph=False,
        )
        second = scanner2.scan()
        check(
            not any(v.get("rule_id") == "SMOKE-SNAPSHOT-001"
                    for v in second["vulnerabilities"]),
            "the next scan no longer sees the deleted rule (hot reload took effect)",
        )

        print("\nALL SMOKE CHECKS PASSED")
    finally:
        server.shutdown()
        shutil.rmtree(TMP_ROOT, ignore_errors=True)


if __name__ == "__main__":
    main()
