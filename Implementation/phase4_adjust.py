"""
SAMVA Phase 4 -- CWE-Aware Priority Adjustment
=================================================
Takes each vulnerability's SCSS score (from Phase 3) and adjusts it based
on how dangerous its weakness CATEGORY (CWE) is known to be in general,
using the CISA/MITRE CWE Top 25 list as a real, external, citable source.

A vulnerability whose weakness type is in the Top 10 most dangerous
categories gets a bigger priority boost than one in ranks 11-25;
anything not on the list stays unchanged.
"""

from config import (
    CWE_TOP_10_WEAKNESS_IDS, CWE_RANKS_11_TO_25_WEAKNESS_IDS,
    CWE_TOP_10_SCORE_MULTIPLIER, CWE_RANKS_11_TO_25_SCORE_MULTIPLIER,
    CWE_NOT_RANKED_SCORE_MULTIPLIER,
)


def cwe_multiplier(cwe_ids):
    """
    Looks at a vulnerability's CWE ID(s) and returns (multiplier, tier_label)
    based on where those CWEs sit on the CISA/MITRE Top 25 list.
    """
    cwe_id_set = set(cwe_ids or [])

    if cwe_id_set & CWE_TOP_10_WEAKNESS_IDS:
        return CWE_TOP_10_SCORE_MULTIPLIER, "cwe_top10"
    if cwe_id_set & CWE_RANKS_11_TO_25_WEAKNESS_IDS:
        return CWE_RANKS_11_TO_25_SCORE_MULTIPLIER, "cwe_top25"
    return CWE_NOT_RANKED_SCORE_MULTIPLIER, "cwe_unranked"


def adjust_finding(scored_record):
    """
    Applies the CWE-based multiplier to one already-scored record,
    producing the final 'adjusted_score' used for prioritised ranking.
    The result is capped at 1.0, since SCSS itself is always 0-1.
    """
    adjusted_record = dict(scored_record)

    has_a_cwe_assigned = bool(scored_record.get("cwe_ids"))
    adjusted_record["cwe_mapped"] = has_a_cwe_assigned

    multiplier, tier_label = cwe_multiplier(scored_record.get("cwe_ids"))
    adjusted_record["cwe_tier"] = tier_label
    adjusted_record["cwe_multiplier"] = multiplier

    if adjusted_record.get("scss") is not None:
        adjusted_record["adjusted_score"] = round(min(adjusted_record["scss"] * multiplier, 1.0), 4)
    else:
        adjusted_record["adjusted_score"] = None

    return adjusted_record


if __name__ == "__main__":
    import sys
    from phase1_ingest import load_trivy_findings
    from phase2_enrich import run_phase2
    from phase3_score import score_finding

    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    raw_findings = load_trivy_findings(trivy_file)
    enriched_findings, _ = run_phase2(raw_findings)
    scored_findings = [score_finding(finding) for finding in enriched_findings]
    adjusted_findings = [adjust_finding(finding) for finding in scored_findings]

    tier_counts = {}
    for finding in adjusted_findings:
        tier_counts[finding["cwe_tier"]] = tier_counts.get(finding["cwe_tier"], 0) + 1
    print("CWE tier distribution:", tier_counts)
