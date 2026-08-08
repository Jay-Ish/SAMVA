"""
SAMVA M5 -- Enrichment Coverage Rate
======================================
Measures what percentage of vulnerabilities ended up with a complete set
of useful fields (CVE ID, CVSS score, CWE category, EPSS score) after
going through SAMVA's full enrichment pipeline.

Works identically for all three scenarios.

Usage:
    python3 compute_m5.py trivy_scenario1.json epss_lookup_scenario1.json nvd_data_lookup_scenario1.json
    python3 compute_m5.py trivy_scenario2.json epss_lookup_scenario2.json nvd_data_lookup_scenario2.json
    python3 compute_m5.py trivy_scenario3.json epss_lookup_scenario3.json nvd_data_lookup_scenario3.json

(The third argument is optional -- without it, records whose CVSS/CWE data
exists only in NVD, not in Trivy's own cache, will be undercounted.)
"""

import json
import sys
import os

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from phase3_score import score_finding
from phase4_adjust import adjust_finding


def compute_m5(adjusted_records, epss_lookup=None):
    """
    Works out M5 (Enrichment Coverage Rate) for one scenario: what
    fraction of findings ended up with a complete CVE ID, CVSS score,
    and CWE category, plus a separate breakdown of how many have an
    EPSS score too. epss_lookup is optional -- pass in the fetched
    EPSS data if you have it, or leave it out to skip that part.
    """
    epss_lookup = epss_lookup or {}
    total_record_count = len(adjusted_records)
    fully_enriched_count = 0

    field_breakdown = {"has_cve": 0, "no_cve": 0, "has_cvss": 0, "no_cvss": 0,
                        "has_cwe": 0, "no_cwe": 0, "has_epss": 0, "no_epss": 0}

    for record in adjusted_records:
        has_a_real_id = bool(record["identifier_resolved"])
        has_complete_cvss = record["cvss_complete"]
        has_a_cwe = bool(record.get("cwe_ids"))
        has_epss_data = record["cve_id"] in epss_lookup

        field_breakdown["has_cve"] += int(has_a_real_id)
        field_breakdown["no_cve"] += int(not has_a_real_id)
        field_breakdown["has_cvss"] += int(has_complete_cvss)
        field_breakdown["no_cvss"] += int(not has_complete_cvss)
        field_breakdown["has_cwe"] += int(has_a_cwe)
        field_breakdown["no_cwe"] += int(not has_a_cwe)
        field_breakdown["has_epss"] += int(has_epss_data)
        field_breakdown["no_epss"] += int(not has_epss_data)

        if has_a_real_id and has_complete_cvss and has_a_cwe:
            fully_enriched_count += 1

    unique_cve_ids = set(record["cve_id"] for record in adjusted_records if record.get("cve_id"))
    unique_cves_with_epss = sum(1 for cve_id in unique_cve_ids if cve_id in epss_lookup)

    return {
        "total_deduplicated_findings": total_record_count,
        "fully_enriched_count": fully_enriched_count,
        "enrichment_coverage_rate_pct": round(100 * fully_enriched_count / total_record_count, 2) if total_record_count else 0,
        "field_level_breakdown": field_breakdown,
        "epss_context": {
            "unique_cves_total": len(unique_cve_ids),
            "unique_cves_with_epss": unique_cves_with_epss,
        },
    }


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    epss_lookup_file = sys.argv[2] if len(sys.argv) > 2 else "epss_lookup.json"
    nvd_lookup_file = sys.argv[3] if len(sys.argv) > 3 else None

    from cwe_fallback import apply_cwe_fallback

    nvd_lookup_table = {}
    if nvd_lookup_file and os.path.exists(nvd_lookup_file):
        with open(nvd_lookup_file) as f:
            nvd_lookup_table = json.load(f)

    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, phase2_stats = run_phase2(raw_findings)
    scored_findings = [score_finding(finding, nvd_lookup_table=nvd_lookup_table) for finding in enriched_findings]
    scored_findings = apply_cwe_fallback(scored_findings, nvd_lookup_table)  # full NVD -> Trivy -> TF-IDF chain
    adjusted_findings = [adjust_finding(finding) for finding in scored_findings]

    epss_lookup = {}
    if os.path.exists(epss_lookup_file):
        with open(epss_lookup_file) as f:
            epss_lookup = json.load(f)

    m5_results = compute_m5(adjusted_findings, epss_lookup)
    print("Phase 2 stats:", json.dumps(phase2_stats, indent=2))
    print()
    print("M5 -- Enrichment Coverage Rate:", json.dumps(m5_results, indent=2))
