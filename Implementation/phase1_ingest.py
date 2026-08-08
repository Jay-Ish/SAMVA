"""
SAMVA Phase 1 -- Scan Ingestion
================================
Reads the raw JSON report produced by a Trivy vulnerability scan and turns
it into a simple, flat list of findings -- one entry per vulnerability
found. This file does NOT clean up or deduplicate anything; that happens
in Phase 2 (see phase2_enrich.py).
"""

import json


def load_trivy_findings(trivy_report_path: str) -> list:
    """
    Reads a Trivy JSON report and returns a list of raw finding dictionaries.

    Each finding includes which part of the application it came from (for
    example 'src/checkoutservice/go.mod'), so later phases can trace a
    vulnerability back to the specific microservice it affects.
    """
    with open(trivy_report_path, "r") as report_file:
        scan_report = json.load(report_file)

    raw_findings = []
    for scan_result in scan_report.get("Results", []):
        source_file_path = scan_result.get("Target", "")
        package_ecosystem = scan_result.get("Type", "")  # e.g. "gomod", "maven", "npm"

        for vulnerability in (scan_result.get("Vulnerabilities") or []):
            raw_findings.append({
                "source_target": source_file_path,
                "source_type": package_ecosystem,
                "raw_cve_id": vulnerability.get("VulnerabilityID"),
                "pkg_name": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "title": vulnerability.get("Title", ""),
                "description": vulnerability.get("Description", ""),
                "severity_raw": vulnerability.get("Severity", ""),
                "cwe_ids_raw": vulnerability.get("CweIDs") or [],
                "cvss_raw": vulnerability.get("CVSS") or {},
                "published_date": vulnerability.get("PublishedDate"),
            })

    return raw_findings


if __name__ == "__main__":
    import sys
    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    findings = load_trivy_findings(trivy_file)
    print(f"Loaded {len(findings)} raw findings from {trivy_file}")
