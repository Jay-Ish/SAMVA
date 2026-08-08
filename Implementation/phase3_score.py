"""
SAMVA Phase 3 -- Severity Scoring
==================================
For each vulnerability, this decides where its CVSS score comes from:

  1. Does Trivy's own scan data already include a complete CVSS v3.1 vector?
     If yes, use it directly -- it's already authoritative.
  2. If not, does the NVD database have one? If yes, use that.
  3. Only if NEITHER source has a usable score does the machine learning
     model get involved (see apply_ml_fallback.py) -- this file only
     marks those records as needing the model's help, it does not run
     the model itself.

Once we have a real, complete 8-metric CVSS vector (from any source), this
file also calculates the SAMVA Composite Severity Score (SCSS), which
combines CVSS severity with EPSS (real-world exploitation likelihood).
"""

from config import (
    IMPACT_WEIGHT, EXPLOITABILITY_WEIGHT, EPSS_WEIGHT,
    IMPACT_MAXIMUM_VALUE, EXPLOITABILITY_MAXIMUM_VALUE,
    ATTACK_VECTOR_WEIGHTS, ATTACK_COMPLEXITY_WEIGHTS, USER_INTERACTION_WEIGHTS,
    PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_UNCHANGED, PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_CHANGED,
    IMPACT_METRIC_WEIGHTS,
)


def parse_cvss_v31_vector(vector_string: str):
    """
    Parses a CVSS v3.1 vector string like:
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
    into a dictionary of the 8 letter codes, or returns None if the
    string is missing or doesn't contain all 8 required fields.
    """
    if not vector_string or "CVSS:3" not in vector_string:
        return None

    metric_values = {}
    for part in vector_string.split("/"):
        if ":" in part:
            metric_name, metric_value = part.split(":", 1)
            metric_values[metric_name] = metric_value

    required_metric_names = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required_metric_names.issubset(metric_values.keys()):
        return None
    return metric_values


def calculate_impact_and_exploitability(metric_values: dict):
    """
    Runs the official CVSS v3.1 formula to calculate the raw Impact and
    Exploitability sub-scores from the 8 metric values.
    Returns (impact_score, exploitability_score), both on CVSS's native
    scale -- NOT yet rescaled to 0-1.
    """
    scope_is_changed = metric_values["S"] == "C"

    confidentiality_weight = IMPACT_METRIC_WEIGHTS[metric_values["C"]]
    integrity_weight = IMPACT_METRIC_WEIGHTS[metric_values["I"]]
    availability_weight = IMPACT_METRIC_WEIGHTS[metric_values["A"]]
    impact_sub_score_base = 1 - (
        (1 - confidentiality_weight) * (1 - integrity_weight) * (1 - availability_weight)
    )

    if scope_is_changed:
        impact_score = 7.52 * (impact_sub_score_base - 0.029) - 3.25 * (
            (impact_sub_score_base - 0.02) ** 15
        )
    else:
        impact_score = 6.42 * impact_sub_score_base
    impact_score = max(impact_score, 0.0)

    attack_vector_weight = ATTACK_VECTOR_WEIGHTS[metric_values["AV"]]
    attack_complexity_weight = ATTACK_COMPLEXITY_WEIGHTS[metric_values["AC"]]
    user_interaction_weight = USER_INTERACTION_WEIGHTS[metric_values["UI"]]
    privileges_required_table = (
        PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_CHANGED if scope_is_changed
        else PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_UNCHANGED
    )
    privileges_required_weight = privileges_required_table[metric_values["PR"]]

    exploitability_score = (
        8.22 * attack_vector_weight * attack_complexity_weight
        * privileges_required_weight * user_interaction_weight
    )

    return impact_score, exploitability_score


def rescale_impact_to_zero_one_range(raw_impact_score: float) -> float:
    """Rescales the Impact sub-score onto a 0-1 range for use in SCSS."""
    return min(raw_impact_score / IMPACT_MAXIMUM_VALUE, 1.0)


def rescale_exploitability_to_zero_one_range(raw_exploitability_score: float) -> float:
    """Rescales the Exploitability sub-score onto a 0-1 range for use in SCSS."""
    return min(raw_exploitability_score / EXPLOITABILITY_MAXIMUM_VALUE, 1.0)


def extract_best_cvss_vector(cvss_data_by_vendor: dict):
    """
    Trivy stores CVSS data separately per data source (nvd, redhat, ghsa,
    and so on). This picks the best one available, preferring NVD first,
    then RedHat, then GHSA, then whatever else is there.
    Returns (vector_string, v3_score) or (None, None) if nothing usable exists.
    """
    if not cvss_data_by_vendor:
        return None, None

    for preferred_vendor in ["nvd", "redhat", "ghsa"]:
        vendor_entry = cvss_data_by_vendor.get(preferred_vendor)
        if vendor_entry and vendor_entry.get("V3Vector"):
            return vendor_entry["V3Vector"], vendor_entry.get("V3Score")

    # None of the preferred vendors had a usable vector -- fall back to
    # whichever vendor's data IS available.
    for vendor_entry in cvss_data_by_vendor.values():
        if vendor_entry and vendor_entry.get("V3Vector"):
            return vendor_entry["V3Vector"], vendor_entry.get("V3Score")

    return None, None


def score_finding(enriched_finding: dict, epss_score: float = None, nvd_lookup_table: dict = None) -> dict:
    """
    Scores one finding: figures out its CVSS vector (from Trivy's cache or
    NVD), calculates Impact/Exploitability if a vector was found, and
    combines everything into the SCSS score.

    If no CVSS vector could be found from either source, this finding is
    marked as needing the machine learning model's help (see
    apply_ml_fallback.py) -- scoring is left incomplete here on purpose.
    """
    nvd_lookup_table = nvd_lookup_table or {}

    cvss_vector_string, cvss_base_score = extract_best_cvss_vector(enriched_finding["cvss_raw"])
    score_source = "trivy_cached" if cvss_vector_string else None

    if not cvss_vector_string:
        nvd_entry = nvd_lookup_table.get(enriched_finding["cve_id"])
        if nvd_entry and nvd_entry.get("cvss_vector"):
            cvss_vector_string = nvd_entry["cvss_vector"]
            cvss_base_score = None  # will be calculated from the vector below
            score_source = "nvd_targeted_lookup"

    metric_values = parse_cvss_v31_vector(cvss_vector_string) if cvss_vector_string else None

    scored_finding = dict(enriched_finding)
    scored_finding["cvss_v3_vector"] = cvss_vector_string
    scored_finding["cvss_v3_score"] = cvss_base_score
    scored_finding["cvss_source"] = score_source
    scored_finding["epss_score"] = epss_score
    scored_finding["epss_available"] = epss_score is not None

    if metric_values:
        scored_finding["cvss_complete"] = True
        raw_impact, raw_exploitability = calculate_impact_and_exploitability(metric_values)
        scored_finding["impact_subscore_norm"] = round(rescale_impact_to_zero_one_range(raw_impact), 4)
        scored_finding["exploitability_subscore_norm"] = round(rescale_exploitability_to_zero_one_range(raw_exploitability), 4)
        scored_finding["inference_required"] = False

        if scored_finding["cvss_v3_score"] is None:
            scored_finding["cvss_v3_score"] = round(min(raw_impact + raw_exploitability, 10.0), 1)
    else:
        # No usable CVSS vector found -- this finding needs the ML model.
        scored_finding["cvss_complete"] = False
        scored_finding["impact_subscore_norm"] = None
        scored_finding["exploitability_subscore_norm"] = None
        scored_finding["inference_required"] = True

    if scored_finding["impact_subscore_norm"] is not None:
        epss_contribution = epss_score if epss_score is not None else 0.0
        scored_finding["scss"] = round(
            IMPACT_WEIGHT * scored_finding["impact_subscore_norm"]
            + EXPLOITABILITY_WEIGHT * scored_finding["exploitability_subscore_norm"]
            + EPSS_WEIGHT * epss_contribution,
            4,
        )
    else:
        scored_finding["scss"] = None

    return scored_finding


if __name__ == "__main__":
    import sys
    from phase1_ingest import load_trivy_findings
    from phase2_enrich import run_phase2

    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    raw_findings = load_trivy_findings(trivy_file)
    enriched_findings, _ = run_phase2(raw_findings)
    scored_findings = [score_finding(finding) for finding in enriched_findings]

    complete_count = sum(1 for f in scored_findings if f["cvss_complete"])
    incomplete_count = sum(1 for f in scored_findings if not f["cvss_complete"])
    print(f"CVSS complete (no ML needed): {complete_count}")
    print(f"CVSS incomplete (needs ML fallback): {incomplete_count}")
