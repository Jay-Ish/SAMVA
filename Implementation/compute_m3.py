"""
SAMVA M3 -- Ranking Correlation
=================================
Checks whether SAMVA's final prioritised ranking (which includes EPSS and
CWE-based adjustments) still stays sensibly close to a plain CVSS-only
ranking. A high correlation here is the GOOD outcome -- it means SAMVA
refines CVSS's ordering with real-world context, rather than replacing
or randomly reshuffling it.

Uses Spearman's rank correlation, matching the exact methodology used by
Koscinski et al. (2025) for comparing vulnerability scoring systems.

Works identically for all three scenarios.

Usage:
    python3 compute_m3.py trivy_scenario1.json nvd_data_lookup_scenario1.json
    python3 compute_m3.py trivy_scenario2.json nvd_data_lookup_scenario2.json
    python3 compute_m3.py trivy_scenario3.json nvd_data_lookup_scenario3.json

(The second argument is optional -- without it, records whose CVSS score
exists only in NVD, not in Trivy's own cache, will be undercounted.)
"""

import json
import sys

from scipy.stats import spearmanr

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from phase3_score import score_finding
from apply_ml_fallback import apply_ml_fallback, add_samva_severity
from cwe_fallback import apply_cwe_fallback
from phase4_adjust import adjust_finding


def run_m3_evaluation(trivy_input_file="trivy_scenario1.json", nvd_lookup_file=None):
    import json as json_module
    import os

    nvd_lookup_table = {}
    if nvd_lookup_file and os.path.exists(nvd_lookup_file):
        with open(nvd_lookup_file) as f:
            nvd_lookup_table = json_module.load(f)

    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)
    scored_findings = [score_finding(finding, nvd_lookup_table=nvd_lookup_table) for finding in enriched_findings]
    scored_findings = apply_ml_fallback(scored_findings)
    scored_findings = add_samva_severity(scored_findings)
    scored_findings = apply_cwe_fallback(scored_findings, nvd_lookup_table)
    adjusted_findings = [adjust_finding(finding) for finding in scored_findings]

    # Compare the FULL SAMVA score (adjusted_score) against plain CVSS
    # (cvss_v3_score) directly -- never against samva_severity, since that
    # is itself CVSS-derived and would make the comparison circular.
    # Counted once per unique CVE, since repeat findings of the same CVE
    # would artificially inflate the sample size without adding real
    # independent information.
    seen_cve_ids = set()
    eligible_findings = []
    for finding in adjusted_findings:
        has_both_scores = finding["adjusted_score"] is not None and finding["cvss_v3_score"] is not None
        if has_both_scores and finding["cve_id"] not in seen_cve_ids:
            eligible_findings.append(finding)
            seen_cve_ids.add(finding["cve_id"])

    samva_scores = [finding["adjusted_score"] for finding in eligible_findings]
    cvss_only_scores = [finding["cvss_v3_score"] for finding in eligible_findings]

    correlation, p_value = spearmanr(samva_scores, cvss_only_scores)

    return {
        "M3_spearman_rank_correlation_vs_cvss_only": round(float(correlation), 4),
        "p_value": round(float(p_value), 6),
        "records_compared": len(eligible_findings),
    }


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    nvd_lookup_file = sys.argv[2] if len(sys.argv) > 2 else None
    print(json.dumps(run_m3_evaluation(trivy_input_file, nvd_lookup_file), indent=2))
