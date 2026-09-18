# -*- coding: utf-8 -*-
"""
Unified Diagnostic and Test Runner for KeenGuard.
Allows executing tests, checklist evaluation, and router connection diagnostics
via a single script without interactive terminal prompt overhead.
"""
import sys
import os
import argparse
import asyncio
import logging
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("diagnostics")


async def run_checklist_diagnostics():
    """Validates Security Checklist evaluator and consistency of all 10 checks."""
    logger.info("=== Running Checklist Diagnostics ===")
    from keenguard.core.checklist import SecurityChecklistEvaluator
    from keenguard.core.keenetic import keenetic_client

    # Test keenetic client methods
    wifi = await keenetic_client.get_wifi_security()
    logger.info("Keenetic Wi-Fi security query: score=%s, APs=%d", wifi.get("score"), len(wifi.get("access_points", [])))

    fw = await keenetic_client.check_firmware_updates()
    logger.info("Keenetic Firmware check: current=%s, has_update=%s", fw.get("current_version"), fw.get("has_update"))

    upnp = await keenetic_client.get_upnp_mappings()
    logger.info("Keenetic UPnP mappings: count=%d", len(upnp))

    dns = await keenetic_client.get_dns_proxy_status()
    logger.info("Keenetic DNS proxy status: engine=%s, doh=%s, dot=%s", dns.get("filter_engine"), dns.get("has_doh"), dns.get("has_dot"))

    # Evaluate full checklist
    res = await SecurityChecklistEvaluator.evaluate_checklist()
    assert res["status"] == "ok", f"Checklist returned invalid status: {res.get('status')}"
    assert len(res["items"]) >= 10, f"Expected at least 10 checklist items, got {len(res['items'])}"

    logger.info("Checklist evaluated successfully: Score=%d/100 (%s)", res["score"], res["score_label"])
    for idx, item in enumerate(res["items"], 1):
        logger.info("  [%d/%d] [%s] %s -> %s", idx, len(res["items"]), item["status"].upper(), item["title"], item["live_status"][:60] + "...")
    logger.info("=== Checklist Diagnostics PASSED ===")
    return True


async def inspect_reports(mac=None):
    import json
    from keenguard.db.database import db
    reports = await db.get_audit_reports(mac=mac, limit=10)
    logger.info("=== Found %d audit reports ===", len(reports))
    for r in reports:
        logger.info("Report ID=%s, MAC=%s (%s), duration_seconds=%s, packets=%s, bytes=%s",
                    r.id, r.mac, r.hostname, r.duration_seconds, r.total_packets, r.total_bytes)
        try:
            data = json.loads(r.report_json)
            logger.info("  start_time=%s, end_time=%s, duration_seconds=%s",
                        data.get("start_time"), data.get("end_time"), data.get("duration_seconds"))
        except Exception as e:
            logger.error("  error parsing report_json: %s", e)

async def inspect_dns():
    from keenguard.db.database import db
    from keenguard.core.domain_analyzer import domain_analyzer
    await domain_analyzer.load_custom_rules_and_signatures(database=db)
    queries = await db.get_top_dns_queries(limit=200)
    logger.info("=== Found %d DNS queries in DB ===", len(queries))
    unknown_list = []
    classified_list = []
    for q in queries:
        dom = q["domain"]
        analysis = domain_analyzer.analyze_domain(dom, ip=q.get("ip"))
        cat = analysis["category"]
        risk = analysis["risk_level"]
        badge_col = analysis["badge_color"]
        if cat == "unknown" or badge_col == "slate":
            unknown_list.append((dom, q.get("count", 1), q.get("mac"), q.get("ip")))
        else:
            classified_list.append((dom, cat, risk, analysis["vendor"]))

    logger.info("=== CLASSIFIED DOMAINS (%d) ===", len(classified_list))
    for dom, cat, risk, vendor in classified_list[:20]:
        logger.info("  [OK] %-35s -> %-15s | %-8s | %s", dom, cat, risk, vendor)

    logger.info("=== UNKNOWN / GRAY (SLATE) DOMAINS (%d) ===", len(unknown_list))
    for dom, cnt, mac, ip in unknown_list:
        logger.info("  [GRAY] %-35s (count=%d, mac=%s, ip=%s)", dom, cnt, mac, ip)
    return len(unknown_list)

def audit_codebase():
    """Performs deep cross-checks between frontend, backend routes, and module methods."""
    import re
    logger.info("=== Running Codebase Deep Audit ===")
    issues = []

    app_js = (PROJECT_ROOT / "keenguard" / "web" / "static" / "app.js").read_text(encoding="utf-8")
    index_html = (PROJECT_ROOT / "keenguard" / "web" / "static" / "index.html").read_text(encoding="utf-8")

    # 1. Endpoint cross-check
    from keenguard.web.app import app
    routes = set()
    for route in app.routes:
        if hasattr(route, "path"):
            routes.add(route.path)

    fetch_matches = re.findall(r"fetch\(\s*['\"`](/api/[^'\"`\?]+)", app_js)
    logger.info("Found %d distinct fetch() calls in app.js", len(set(fetch_matches)))
    for f in set(fetch_matches):
        normalized = re.sub(r"\$\{[^}]+\}", "{param}", f)
        matched = False
        for r in routes:
            r_norm = re.sub(r"\{[^}]+\}", "{param}", r)
            if normalized == r_norm:
                matched = True
                break
        if not matched:
            issues.append(f"UNMATCHED_ENDPOINT: app.js calls '{f}', but no matching route found in app.py!")

    # 2. DOM ID cross-check
    dom_matches = re.findall(r"document\.getElementById\(['\"]([^'\"]+)['\"]\)", app_js)
    html_ids = set(re.findall(r'id=["\']([^"\']+)["\']', index_html))
    logger.info("Found %d distinct getElementById calls, %d IDs in index.html", len(set(dom_matches)), len(html_ids))
    for dom_id in set(dom_matches):
        if dom_id not in html_ids:
            if f'id="${dom_id}' not in app_js and f'id="{dom_id}' not in app_js and f"id='{dom_id}" not in app_js:
                issues.append(f"MISSING_DOM_ID: app.js accesses document.getElementById('{dom_id}'), but it is not defined in index.html!")

    # 3. KeeneticClient method calls
    from keenguard.core.keenetic import KeeneticClient
    client_methods = set(dir(KeeneticClient))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\bkeenetic_client\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in client_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_METHOD: {py_file.name} calls keenetic_client.{call}(), which does not exist!")

    # 4. Database method calls
    from keenguard.db.database import Database
    db_methods = set(dir(Database))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\bdb\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in db_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_DB_METHOD: {py_file.name} calls db.{call}(), which does not exist!")

    # 5. Sniffer, Forensics, Anomaly, AuditManager method calls
    from keenguard.core.sniffer import NetworkSniffer
    sniffer_methods = set(dir(NetworkSniffer))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\bsniffer\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in sniffer_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_SNIFFER_METHOD: {py_file.name} calls sniffer.{call}(), which does not exist!")

    from keenguard.core.forensics import ForensicsEngine
    forensics_methods = set(dir(ForensicsEngine))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\bforensics_engine\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in forensics_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_FORENSICS_METHOD: {py_file.name} calls forensics_engine.{call}(), which does not exist!")

    from keenguard.core.anomaly import AnomalyDetector
    anomaly_methods = set(dir(AnomalyDetector))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\banomaly_detector\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in anomaly_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_ANOMALY_METHOD: {py_file.name} calls anomaly_detector.{call}(), which does not exist!")

    from keenguard.core.audit import TrafficAuditManager
    audit_methods = set(dir(TrafficAuditManager))
    for py_file in (PROJECT_ROOT / "keenguard").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        calls = re.findall(r"\baudit_manager\.([a-zA-Z0-9_]+)\(", content)
        for call in calls:
            if call not in audit_methods and not call.startswith("_"):
                issues.append(f"UNKNOWN_AUDIT_METHOD: {py_file.name} calls audit_manager.{call}(), which does not exist!")

    # 6. Model fields check
    from keenguard.db.models import DeviceRecord, SecurityEvent
    from keenguard.core.keenetic import UPnPMapping
    dev_fields = set(DeviceRecord.model_fields.keys())
    event_fields = set(SecurityEvent.model_fields.keys())
    upnp_fields = set(UPnPMapping.model_fields.keys())

    # 7. Inspect Math and toFixed calls
    for line_no, line in enumerate(app_js.splitlines(), 1):
        if ("Math." in line or "toFixed(" in line) and not line.strip().startswith("//"):
            logger.info("MATH_OP app.js:%d -> %s", line_no, line.strip())

    logger.info("=== Audit Completed. Found %d potential issues ===", len(issues))
    for iss in issues:
        logger.warning("  [!] %s", iss)
    return issues


def run_pytest_suite(test_target=None):
    """Executes pytest unit test suite."""
    logger.info("=== Running Pytest Suite ===")
    import pytest
    args = ["-v", test_target or str(PROJECT_ROOT / "tests")]
    exit_code = pytest.main(args)
    if exit_code == 0:
        logger.info("=== Pytest Suite PASSED ===")
        return True
    else:
        logger.error("=== Pytest Suite FAILED with exit code %s ===", exit_code)
        return False


def main():
    parser = argparse.ArgumentParser(description="KeenGuard Diagnostics & Test Runner")
    parser.add_argument("--pytest", action="store_true", help="Run pytest suite")
    parser.add_argument("--checklist", action="store_true", help="Run checklist diagnostics")
    parser.add_argument("--audit", action="store_true", help="Run full cross-module static and route audit")
    parser.add_argument("--reports", action="store_true", help="Inspect audit reports in DB")
    parser.add_argument("--dns", action="store_true", help="Inspect and classify DNS queries in DB")
    parser.add_argument("--test-target", type=str, default=None, help="Target test file or dir")
    parser.add_argument("--mac", type=str, default="44:87:63:37:C2:52", help="MAC address for report inspection")
    args = parser.parse_args()

    run_all = not (args.pytest or args.checklist or args.reports or args.audit or args.dns)
    success = True

    if args.audit or run_all:
        try:
            audit_issues = audit_codebase()
            if audit_issues:
                # Flag as failed if there are severe bugs
                severe = [i for i in audit_issues if "UNKNOWN_METHOD" in i or "UNMATCHED_ENDPOINT" in i or "ROUND_DURATION_BUG" in i]
                if severe:
                    success = False
        except Exception as e:
            logger.exception("Codebase audit failed: %s", e)
            success = False

    if args.reports:
        try:
            asyncio.run(inspect_reports(args.mac))
        except Exception as e:
            logger.exception("Inspect reports failed: %s", e)
            success = False

    if args.dns:
        try:
            asyncio.run(inspect_dns())
        except Exception as e:
            logger.exception("Inspect DNS failed: %s", e)
            success = False

    if args.checklist or run_all:
        try:
            cl_ok = asyncio.run(run_checklist_diagnostics())
            if not cl_ok:
                success = False
        except Exception as e:
            logger.exception("Checklist diagnostics failed with error: %s", e)
            success = False

    if args.pytest or run_all:
        try:
            pt_ok = run_pytest_suite(args.test_target)
            if not pt_ok:
                success = False
        except Exception as e:
            logger.exception("Pytest execution failed: %s", e)
            success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
