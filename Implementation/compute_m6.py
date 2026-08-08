"""
SAMVA M6 -- Directional Update Accuracy
==========================================
Checks whether SAMVA correctly moves a vulnerability's priority UP or DOWN
when real-world exploitation likelihood (EPSS) genuinely changes over time.
This tests SAMVA's "self-adaptive" claim directly: does new intelligence
actually change the ranking in the right direction?

Uses two real historical EPSS dates (see fetch_epss_historical.py) rather
than waiting weeks for two live observations to happen naturally.

Works identically for all three scenarios.

Usage:
    python3 compute_m6.py trivy_scenario1.json epss_historical_scenario1.json nvd_data_lookup_scenario1.json
    python3 compute_m6.py trivy_scenario2.json epss_historical_scenario2.json nvd_data_lookup_scenario2.json
    python3 compute_m6.py trivy_scenario3.json epss_historical_scenario3.json nvd_data_lookup_scenario3.json

(The third argument is optional -- without it, records whose CVSS data
exists only in NVD, not in Trivy's own cache, will be undercounted.)
"""

import json
import sys
import os

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from phase3_score import score_finding
from apply_ml_fallback import apply_ml_fallback
from phase4_adjust import adjust_finding
from config import EPSS_MEANINGFUL_CHANGE_THRESHOLD


def _evaluate_one_cve_direction(record, epss_score_early, epss_score_late, nvd_lookup_table=None):
    """Checks whether SAMVA's score moved the same direction as the real EPSS change."""
    if abs(epss_score_late - epss_score_early) < EPSS_MEANINGFUL_CHANGE_THRESHOLD:
        return None  # not a meaningful change -- skip, this is just noise

    scored_early = score_finding(record, epss_score=epss_score_early, nvd_lookup_table=nvd_lookup_table)
    scored_early = apply_ml_fallback([scored_early])[0]
    adjusted_early = adjust_finding(scored_early)

    scored_late = score_finding(record, epss_score=epss_score_late, nvd_lookup_table=nvd_lookup_table)
    scored_late = apply_ml_fallback([scored_late])[0]
    adjusted_late = adjust_finding(scored_late)

    if adjusted_early["adjusted_score"] is None or adjusted_late["adjusted_score"] is None:
        return None

    score_change = adjusted_late["adjusted_score"] - adjusted_early["adjusted_score"]
    true_direction = "up" if epss_score_late > epss_score_early else "down"
    samva_predicted_direction = "up" if score_change > 0 else ("down" if score_change < 0 else "flat")

    return {
        "epss_early": epss_score_early,
        "epss_late": epss_score_late,
        "epss_change": round(epss_score_late - epss_score_early, 4),
        "true_direction": true_direction,
        "predicted_direction": samva_predicted_direction,
        "correct": samva_predicted_direction == true_direction,
    }


def _describe_reliability(sample_size):
    """Describes how much confidence a result of this sample size actually supports."""
    if sample_size == 0:
        return "No CVEs in this scenario had a meaningful EPSS change over the comparison window -- no directional result to report."
    if sample_size < 10:
        return f"Only {sample_size} CVEs met the movement threshold -- a preliminary result, not strong evidence."
    if sample_size < 30:
        return f"Sample size ({sample_size} CVEs) is modest -- report alongside the sample size, not as a standalone percentage."
    return f"Sample size ({sample_size} CVEs) supports reasonable confidence in this result."


def run_m6_evaluation(trivy_input_file="trivy_scenario1.json", epss_historical_file="epss_historical_lookup.json", nvd_lookup_file=None):
    nvd_lookup_table = {}
    if nvd_lookup_file and os.path.exists(nvd_lookup_file):
        with open(nvd_lookup_file) as f:
            nvd_lookup_table = json.load(f)

    historical_epss_lookup = {}
    if os.path.exists(epss_historical_file):
        with open(epss_historical_file) as f:
            historical_epss_lookup = json.load(f)

    date_early, date_late = None, None
    if historical_epss_lookup:
        sample_entry = next(iter(historical_epss_lookup.values()))
        date_early = sample_entry["date_early"]["date"]
        date_late = sample_entry["date_late"]["date"]

    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)

    seen_cve_ids = set()
    eligible_records = []
    for record in enriched_findings:
        if record["cve_id"] in historical_epss_lookup and record["cve_id"] not in seen_cve_ids:
            eligible_records.append(record)
            seen_cve_ids.add(record["cve_id"])

    # Deliberately no early exit for a small or even empty sample here.
    # A genuinely small result, reported honestly with its real sample
    # size and a reliability note, is more useful than stopping partway
    # through. Some scenarios naturally have very few CVEs old enough to
    # have existed on the earlier comparison date, and that is itself a
    # real finding worth reporting, not a failure state.

    all_scored_findings = [score_finding(record, nvd_lookup_table=nvd_lookup_table) for record in enriched_findings]
    apply_ml_fallback(all_scored_findings, use_cache=True)

    correct_direction_count = 0
    total_evaluated_count = 0
    per_cve_results = []

    for record in eligible_records:
        cve_id = record["cve_id"]
        epss_early = historical_epss_lookup[cve_id]["date_early"]["epss"]
        epss_late = historical_epss_lookup[cve_id]["date_late"]["epss"]
        result = _evaluate_one_cve_direction(record, epss_early, epss_late, nvd_lookup_table)
        if result is None:
            continue
        total_evaluated_count += 1
        correct_direction_count += int(result["correct"])
        per_cve_results.append({"cve_id": cve_id, **result})

    accuracy_pct = round(100 * correct_direction_count / total_evaluated_count, 2) if total_evaluated_count else 0.0

    return {
        "M6_directional_update_accuracy_pct": accuracy_pct,
        "date_early": date_early,
        "date_late": date_late,
        "cves_evaluated": total_evaluated_count,
        "cves_with_epss_at_both_dates": len(eligible_records),
        "noise_threshold": EPSS_MEANINGFUL_CHANGE_THRESHOLD,
        "reliability_note": _describe_reliability(total_evaluated_count),
        "sample_results": per_cve_results,
    }


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    epss_historical_file = sys.argv[2] if len(sys.argv) > 2 else "epss_historical_lookup.json"
    nvd_lookup_file = sys.argv[3] if len(sys.argv) > 3 else None
    print(json.dumps(run_m6_evaluation(trivy_input_file, epss_historical_file, nvd_lookup_file), indent=2))
