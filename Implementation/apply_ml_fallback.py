"""
SAMVA Phase 3 (continued) -- Machine Learning Fallback
========================================================
Some vulnerabilities don't have a complete CVSS score anywhere (not in
Trivy's cache, not in NVD). For those, this file uses SAMVA's trained
machine learning model to PREDICT what the 8 CVSS metrics probably are,
based on the vulnerability's text description.

Important design choice: the model only ever predicts the 8 individual
metric letter codes (like "Attack Vector is probably Network"). It NEVER
predicts a severity score directly. Once the 8 metrics are predicted, the
real, official CVSS v3.1 formula (see cvss_v31.py) turns them into a Base
Score -- exactly the same formula used for vulnerabilities that already
had a real, authoritative score. This keeps every result standard-compliant,
whether it came from NVD or from the model.
"""

import joblib

from cvss_v31 import CvssVector, compute_base_score
from config import IMPACT_WEIGHT, EXPLOITABILITY_WEIGHT, EPSS_WEIGHT, IMPACT_MAXIMUM_VALUE, EXPLOITABILITY_MAXIMUM_VALUE

THE_8_CVSS_METRIC_NAMES = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
FROZEN_MODEL_FILE_NAME = "refined_model_frozen.joblib"

# Loaded once and reused, instead of reloading the model from disk on
# every single call -- this matters because M6 (temporal reassessment)
# calls this function many times in a row.
_model_loaded_into_memory = None


def severity_from_score(cvss_score):
    """Turns a numeric CVSS score into FIRST's official severity band."""
    if cvss_score is None:
        return "UNKNOWN"
    if cvss_score == 0.0:
        return "NONE"
    if cvss_score < 4.0:
        return "LOW"
    if cvss_score < 7.0:
        return "MEDIUM"
    if cvss_score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _load_the_frozen_model():
    """Loads the already-trained model bundle (vectorizer + 8 classifiers + 8 label encoders)."""
    return joblib.load(FROZEN_MODEL_FILE_NAME)


def _predict_all_8_metrics(model_bundle, description_text):
    """Uses the trained model to guess all 8 CVSS metric values from one description."""
    text_vectorizer = model_bundle["vectorizer"]
    text_features = text_vectorizer.transform([description_text])

    predicted_metric_values = {}
    for metric_name in THE_8_CVSS_METRIC_NAMES:
        classifier_for_this_metric = model_bundle["per_metric_models"][metric_name]
        label_encoder_for_this_metric = model_bundle["per_metric_encoders"][metric_name]

        predicted_label_number = classifier_for_this_metric.predict(text_features)[0]
        predicted_letter_code = label_encoder_for_this_metric.inverse_transform([predicted_label_number])[0]
        predicted_metric_values[metric_name] = predicted_letter_code

    return predicted_metric_values


def apply_ml_fallback(scored_records, use_cache=True):
    """
    Fills in a real CVSS assessment for every record that's missing one
    (cvss_complete == False), using the trained model. Records that
    already have a complete, authoritative CVSS score are returned
    completely unchanged.

    use_cache=True (the default) keeps the model loaded in memory between
    calls, instead of reloading it from disk every time -- important for
    M6, which calls this function many times.
    """
    global _model_loaded_into_memory
    if use_cache and _model_loaded_into_memory is not None:
        model_bundle = _model_loaded_into_memory
    else:
        model_bundle = _load_the_frozen_model()
        if use_cache:
            _model_loaded_into_memory = model_bundle

    records_needing_a_prediction = [record for record in scored_records if not record["cvss_complete"]]
    if not records_needing_a_prediction:
        return scored_records  # nothing to do -- every record already has a real score

    updated_records = []
    for record in scored_records:
        record = dict(record)  # work on a copy, never modify the original

        if not record["cvss_complete"]:
            description_text = (record.get("description") or "").strip()

            if not description_text:
                # There is no CVSS score AND no text to predict from --
                # do not guess. Keep the record, but mark it honestly.
                record["cvss_v3_score"] = None
                record["impact_subscore_norm"] = None
                record["exploitability_subscore_norm"] = None
                record["cvss_source"] = "insufficient_data"
                record["scss"] = None
                updated_records.append(record)
                continue

            predicted_metrics = _predict_all_8_metrics(model_bundle, description_text)

            # The model's job stops here -- it only predicted 8 letter
            # codes. The REAL, official CVSS formula does everything else.
            formula_result = compute_base_score(CvssVector(
                attack_vector=predicted_metrics["AV"],
                attack_complexity=predicted_metrics["AC"],
                privileges_required=predicted_metrics["PR"],
                user_interaction=predicted_metrics["UI"],
                scope=predicted_metrics["S"],
                confidentiality=predicted_metrics["C"],
                integrity=predicted_metrics["I"],
                availability=predicted_metrics["A"],
            ))

            impact_rescaled = min(formula_result["impact_subscore"] / IMPACT_MAXIMUM_VALUE, 1.0)
            exploitability_rescaled = min(formula_result["exploitability_subscore"] / EXPLOITABILITY_MAXIMUM_VALUE, 1.0)

            record["cvss_v3_score"] = formula_result["base_score"]
            record["cvss_v3_vector"] = (
                f"CVSS:3.1/AV:{predicted_metrics['AV']}/AC:{predicted_metrics['AC']}/"
                f"PR:{predicted_metrics['PR']}/UI:{predicted_metrics['UI']}/S:{predicted_metrics['S']}/"
                f"C:{predicted_metrics['C']}/I:{predicted_metrics['I']}/A:{predicted_metrics['A']}"
            )
            record["impact_subscore_norm"] = round(impact_rescaled, 4)
            record["exploitability_subscore_norm"] = round(exploitability_rescaled, 4)
            record["cvss_source"] = "ml_fallback_predicted"

            epss_contribution = record["epss_score"] if record.get("epss_score") is not None else 0.0
            record["scss"] = round(
                IMPACT_WEIGHT * record["impact_subscore_norm"]
                + EXPLOITABILITY_WEIGHT * record["exploitability_subscore_norm"]
                + EPSS_WEIGHT * epss_contribution,
                4,
            )
        updated_records.append(record)

    return updated_records


def add_samva_severity(records):
    """
    Adds a 'samva_severity' label to every record, worked out from its
    CVSS score no matter where that score came from (Trivy's cache, NVD,
    or the ML model). The scanner's original severity label is never
    changed -- this new field sits alongside it.
    """
    updated_records = []
    for record in records:
        record = dict(record)
        record["samva_severity"] = severity_from_score(record.get("cvss_v3_score"))
        updated_records.append(record)
    return updated_records


if __name__ == "__main__":
    import sys
    from phase1_ingest import load_trivy_findings
    from phase2_enrich import run_phase2
    from phase3_score import score_finding

    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    raw_findings = load_trivy_findings(trivy_file)
    enriched_findings, _ = run_phase2(raw_findings)
    scored_findings = [score_finding(finding) for finding in enriched_findings]

    print(f"Before ML fallback: {sum(1 for f in scored_findings if f['scss'] is None)} records with no score")
    filled_findings = apply_ml_fallback(scored_findings)
    print(f"After ML fallback:  {sum(1 for f in filled_findings if f['scss'] is None)} records with no score")
