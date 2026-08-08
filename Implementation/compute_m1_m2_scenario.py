"""
SAMVA M1 / M2 -- Scenario-Level Evaluation
=============================================
Checks how accurately SAMVA's model predicts the 8 real CVSS metrics for
one application's own vulnerabilities. This is measured PRIMARILY on the
8 individual metrics (the model's real, direct output), with the final
derived severity reported separately as a secondary result -- since
severity depends on all 8 metrics combining correctly, not just one.

This is SECONDARY, scenario-level evidence. The PRIMARY, official M1/M2
result is the large held-out NVD test set (see evaluate_final.py) --
this file exists to show how the same, unchanged model performs on real,
specific applications, not to replace the main result.

Works identically for all three scenarios -- just point it at a different
Trivy scan file.

Usage:
    python3 compute_m1_m2_scenario.py trivy_scenario1.json nvd_data_lookup_scenario1.json
    python3 compute_m1_m2_scenario.py trivy_scenario2.json nvd_data_lookup_scenario2.json
    python3 compute_m1_m2_scenario.py trivy_scenario3.json nvd_data_lookup_scenario3.json

(The second argument is optional -- without it, records whose CVSS score
exists only in NVD, not in Trivy's own cache, will be undercounted.)
"""

import json
import sys

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, mean_absolute_error

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from phase3_score import score_finding, parse_cvss_v31_vector
from cvss_v31 import CvssVector, compute_base_score

FROZEN_MODEL_FILE_NAME = "refined_model_frozen.joblib"
THE_8_CVSS_METRIC_NAMES = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def severity_bucket(cvss_score):
    """FIRST's official CVSS v3.1 severity bands."""
    if cvss_score is None:
        return None
    if cvss_score == 0.0:
        return "NONE"
    if cvss_score < 4.0:
        return "LOW"
    if cvss_score < 7.0:
        return "MEDIUM"
    if cvss_score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _load_training_cve_ids():
    """
    Reads every CVE ID used anywhere in the model's training pipeline
    (train, validation, and the official held-out test split). Records
    matching any of these need to be excluded from a scenario evaluation,
    since the model may have already seen the correct answer for them
    during training -- that would not be a fair test of generalisation.
    """
    import os
    all_training_cve_ids = set()
    files_found = 0
    for file_name in ["train_set_used.csv", "validation_set_clean.csv", "test_set_held_out.csv"]:
        if os.path.exists(file_name):
            files_found += 1
            df = pd.read_csv(file_name)
            id_column = "cve_id" if "cve_id" in df.columns else df.columns[0]
            all_training_cve_ids |= set(df[id_column].astype(str))

    if files_found == 0:
        print("WARNING: none of train_set_used.csv, validation_set_clean.csv, or "
              "test_set_held_out.csv were found in this folder. The training-overlap "
              "check cannot run, so results below may include leaked CVEs without "
              "any warning otherwise. Copy those 3 files into this folder before "
              "trusting these numbers.")

    return all_training_cve_ids


def build_ground_truth_set(trivy_input_file, nvd_lookup_file=None, exclude_training_overlap=True):
    """
    Collects only the records that already have a real, known CVSS score
    -- these are the only ones we can honestly check a prediction against.
    Each unique CVE is counted once, even if it affects several services,
    since the same CVE always gets the same description and score.

    nvd_lookup_file: optional path to a nvd_data_lookup_*.json file (from
    fetch_nvd_data.py) -- without this, records whose CVSS score exists
    only in NVD (not in Trivy's own cache) would be incorrectly treated
    as missing a score.

    exclude_training_overlap: when True (the default), any CVE that also
    appears in the model's own training/validation/test data is removed
    from the evaluation set. Some real applications' dependencies do
    genuinely overlap with the training period, and including those
    records would let the model answer from memory rather than genuine
    prediction -- excluding them keeps this a fair, out-of-sample test.
    """
    import json
    import os

    nvd_lookup_table = {}
    if nvd_lookup_file and os.path.exists(nvd_lookup_file):
        with open(nvd_lookup_file) as f:
            nvd_lookup_table = json.load(f)

    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)
    scored_findings = [score_finding(finding, nvd_lookup_table=nvd_lookup_table) for finding in enriched_findings]

    training_cve_ids = _load_training_cve_ids() if exclude_training_overlap else set()
    excluded_count = 0

    seen_cve_ids = set()
    ground_truth_records = []
    for finding in scored_findings:
        has_real_score = finding["cvss_complete"] and finding["cvss_v3_score"] is not None
        if not has_real_score or finding["cve_id"] in seen_cve_ids:
            continue
        if finding["cve_id"] in training_cve_ids:
            excluded_count += 1
            seen_cve_ids.add(finding["cve_id"])
            continue
        ground_truth_records.append(finding)
        seen_cve_ids.add(finding["cve_id"])

    return ground_truth_records, len(scored_findings), excluded_count


def run_scenario_evaluation(trivy_input_file, scenario_name="scenario", nvd_lookup_file=None):
    """Runs the full scenario-level M1/M2 evaluation and returns a results dictionary."""
    ground_truth_records, total_scenario_records, excluded_leak_count = build_ground_truth_set(trivy_input_file, nvd_lookup_file)

    if len(ground_truth_records) < 5:
        return {"error": f"Only {len(ground_truth_records)} ground-truth records -- too few for a meaningful check."}

    model_bundle = joblib.load(FROZEN_MODEL_FILE_NAME)
    text_vectorizer = model_bundle["vectorizer"]
    description_texts = [record["description"] for record in ground_truth_records]
    text_features = text_vectorizer.transform(description_texts)

    predicted_metrics_per_record = []
    for record_index in range(len(ground_truth_records)):
        predicted_metrics = {}
        for metric_name in THE_8_CVSS_METRIC_NAMES:
            classifier = model_bundle["per_metric_models"][metric_name]
            label_encoder = model_bundle["per_metric_encoders"][metric_name]
            predicted_label = classifier.predict(text_features[record_index])[0]
            predicted_metrics[metric_name] = label_encoder.inverse_transform([predicted_label])[0]
        predicted_metrics_per_record.append(predicted_metrics)
    predicted_metrics_dataframe = pd.DataFrame(predicted_metrics_per_record)

    true_metrics_per_record = []
    for record in ground_truth_records:
        parsed_vector = parse_cvss_v31_vector(record.get("cvss_v3_vector"))
        true_metrics_per_record.append(parsed_vector if parsed_vector else {name: None for name in THE_8_CVSS_METRIC_NAMES})
    true_metrics_dataframe = pd.DataFrame(true_metrics_per_record)

    # --- PRIMARY result: how accurate is each of the 8 metrics individually? ---
    per_metric_results = {}
    for metric_name in THE_8_CVSS_METRIC_NAMES:
        has_valid_ground_truth = true_metrics_dataframe[metric_name].notna()
        true_values = true_metrics_dataframe.loc[has_valid_ground_truth, metric_name]
        predicted_values = predicted_metrics_dataframe.loc[has_valid_ground_truth, metric_name]
        if len(true_values) == 0:
            continue
        per_metric_results[metric_name] = {
            "accuracy_pct": round(accuracy_score(true_values, predicted_values) * 100, 2),
            "macro_f1_pct": round(f1_score(true_values, predicted_values, average="macro", zero_division=0) * 100, 2),
            "precision_macro_pct": round(precision_score(true_values, predicted_values, average="macro", zero_division=0) * 100, 2),
            "recall_macro_pct": round(recall_score(true_values, predicted_values, average="macro", zero_division=0) * 100, 2),
            "sample_size": int(has_valid_ground_truth.sum()),
        }

    average_accuracy_across_metrics = round(sum(m["accuracy_pct"] for m in per_metric_results.values()) / len(per_metric_results), 2)
    average_macro_f1_across_metrics = round(sum(m["macro_f1_pct"] for m in per_metric_results.values()) / len(per_metric_results), 2)

    # --- SECONDARY result: derived severity (all 8 metrics combined via the official formula) ---
    predicted_base_scores = []
    for predicted_metrics in predicted_metrics_per_record:
        formula_result = compute_base_score(CvssVector(
            attack_vector=predicted_metrics["AV"], attack_complexity=predicted_metrics["AC"],
            privileges_required=predicted_metrics["PR"], user_interaction=predicted_metrics["UI"],
            scope=predicted_metrics["S"], confidentiality=predicted_metrics["C"],
            integrity=predicted_metrics["I"], availability=predicted_metrics["A"],
        ))
        predicted_base_scores.append(formula_result["base_score"])

    true_scores = [record["cvss_v3_score"] for record in ground_truth_records]
    true_severity_buckets = [severity_bucket(score) for score in true_scores]
    predicted_severity_buckets = [severity_bucket(score) for score in predicted_base_scores]

    severity_result = {
        "accuracy_pct": round(accuracy_score(true_severity_buckets, predicted_severity_buckets) * 100, 2),
        "macro_f1_pct": round(f1_score(true_severity_buckets, predicted_severity_buckets, average="macro", zero_division=0) * 100, 2),
        "mae": round(mean_absolute_error(true_scores, predicted_base_scores), 4),
        "sample_size": len(ground_truth_records),
    }

    return {
        "scenario": scenario_name,
        "primary_per_metric_results": per_metric_results,
        "primary_average_across_8_metrics": {
            "accuracy_pct": average_accuracy_across_metrics,
            "macro_f1_pct": average_macro_f1_across_metrics,
        },
        "secondary_derived_severity": severity_result,
        "dataset_info": {
            "total_scenario_records": total_scenario_records,
            "ground_truth_records_used": len(ground_truth_records),
            "excluded_due_to_training_overlap": excluded_leak_count,
        },
    }


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    nvd_lookup_file = sys.argv[2] if len(sys.argv) > 2 else None
    scenario_name = trivy_input_file.replace("trivy_", "").replace(".json", "")

    results = run_scenario_evaluation(trivy_input_file, scenario_name, nvd_lookup_file)
    print(json.dumps(results, indent=2))
