"""
SAMVA Phase 2 -- Cleanup and Enrichment
=========================================
Takes the raw findings from Phase 1 and:
  1. Removes exact duplicate findings (the same vulnerability reported
     twice for the same package in the same file).
  2. Standardises messy fields into a consistent format (severity labels,
     CWE identifiers).
  3. Figures out whether each finding has a real, usable CVE identifier.
"""

import re


def normalise_severity_label(raw_severity: str) -> str:
    """Turns Trivy's severity text into a clean, consistent uppercase label."""
    if not raw_severity:
        return "UNKNOWN"
    return raw_severity.strip().upper()


def normalise_cwe_id_list(raw_cwe_ids: list) -> list:
    """Makes sure every CWE ID looks like 'CWE-123', not just '123'."""
    cleaned_ids = []
    for cwe_id in raw_cwe_ids or []:
        cwe_id = cwe_id.strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        cleaned_ids.append(cwe_id)
    return cleaned_ids


def remove_duplicate_findings(raw_findings: list) -> list:
    """
    Removes EXACT duplicates -- the same CVE reported against the same
    package in the same file more than once. This can happen when a
    package is referenced by more than one manifest entry.
    """
    seen_combinations = set()
    unique_findings = []
    for finding in raw_findings:
        combination_key = (finding["raw_cve_id"], finding["pkg_name"], finding["source_target"])
        if combination_key in seen_combinations:
            continue
        seen_combinations.add(combination_key)
        unique_findings.append(finding)
    return unique_findings


def enrich_one_finding(raw_finding: dict) -> dict:
    """Turns one raw finding into a clean, standardised record."""
    raw_id = raw_finding["raw_cve_id"]
    is_real_cve_format = bool(raw_id and re.match(r"^CVE-\d{4}-\d+$", raw_id))
    is_ghsa_advisory_format = bool(raw_id and re.match(r"^GHSA-", raw_id))

    # Which microservice does this finding belong to? Trivy's Target path
    # usually looks like "src/checkoutservice/go.mod" -- we want just
    # "checkoutservice" as the readable service name.
    if "/" in raw_finding["source_target"]:
        service_name = raw_finding["source_target"].split("/")[1]
    else:
        service_name = raw_finding["source_target"]

    return {
        "cve_id": raw_id,
        "cve_id_resolved": is_real_cve_format,
        "identifier_resolved": is_real_cve_format or is_ghsa_advisory_format,
        "identifier_type": "CVE" if is_real_cve_format else ("GHSA" if is_ghsa_advisory_format else "UNRESOLVED"),
        "service": service_name,
        "source_target": raw_finding["source_target"],
        "ecosystem": raw_finding["source_type"],
        "pkg_name": raw_finding["pkg_name"],
        "installed_version": raw_finding["installed_version"],
        "fixed_version": raw_finding["fixed_version"],
        "description": raw_finding["description"] or raw_finding["title"],
        "raw_severity": normalise_severity_label(raw_finding["severity_raw"]),
        "cwe_ids": normalise_cwe_id_list(raw_finding["cwe_ids_raw"]),
        "cvss_raw": raw_finding["cvss_raw"],
        "published_date": raw_finding["published_date"],
    }


def run_phase2(raw_findings: list):
    """
    Runs the full Phase 2 process: deduplicate, then enrich every finding.
    Returns (list of enriched findings, a small dictionary of stats).
    """
    deduplicated_findings = remove_duplicate_findings(raw_findings)
    enriched_findings = [enrich_one_finding(finding) for finding in deduplicated_findings]

    stats = {
        "raw_count": len(raw_findings),
        "dedup_count": len(deduplicated_findings),
        "dup_removed": len(raw_findings) - len(deduplicated_findings),
        "no_cve": sum(1 for finding in enriched_findings if not finding["cve_id_resolved"]),
    }
    return enriched_findings, stats


if __name__ == "__main__":
    import sys
    from phase1_ingest import load_trivy_findings

    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    raw_findings = load_trivy_findings(trivy_file)
    enriched_findings, stats = run_phase2(raw_findings)
    print("Phase 2 stats:", stats)
