"""
FINAL evaluation on the held-out test set. This script is read-only with
respect to the frozen models -- it loads them, transforms text, predicts,
and compares against ground truth. It never trains, fits, or tunes anything.

Safeguards (all verified further down, and independently searchable):
  - No .fit( or .fit_transform( anywhere in this file.
  - No train_test_split( anywhere in this file -- the split already happened
    once, earlier, and is not repeated here.
  - Only .transform() and .predict() are used on the frozen model objects.
  - Ground truth (from the test CSV) and predictions (from the models) are
    kept in separate variables throughout, never overwritten into each other.
  - If any test record turned out to be unusable, its count and the reason
    would be printed here, not silently dropped -- in this run, the earlier
    data-integrity pass already confirmed zero unusable records, so none are
    expected, but the check itself still runs rather than assuming that.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import f1_score, accuracy_score, mean_absolute_error

from cvss_v31 import CvssVector, compute_base_score

CVSS_METRIC_KEYS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def derive_severity_label(base_score: float) -> str:
    if base_score == 0.0:
        return "None"
    elif base_score < 4.0:
        return "Low"
    elif base_score < 7.0:
        return "Medium"
    elif base_score < 9.0:
        return "High"
    else:
        return "Critical"


def main():
    test_df = pd.read_csv("test_set_held_out.csv")
    print(f"Loaded held-out test set: {len(test_df)} records (opened once, for final evaluation only)")

    # Transparent check for unusable records -- reported, never silently dropped.
    unusable_mask = test_df["description"].isna() | (test_df["description"].str.strip() == "")
    if unusable_mask.sum() > 0:
        print(f"WARNING: {unusable_mask.sum()} test records have no usable description "
              f"and will be excluded from CVSS-prediction metrics (exclusion rule: empty/NaN description).")
    usable_test_df = test_df[~unusable_mask].copy()

    baseline_bundle = joblib.load("baseline_model_frozen.joblib")
    refined_bundle = joblib.load("refined_model_frozen.joblib")

    # ---- Ground truth, kept separate from predictions throughout ----
    ground_truth_metrics = usable_test_df[CVSS_METRIC_KEYS].copy()
    ground_truth_base_score = usable_test_df["nvd_base_score"].copy()
    ground_truth_severity = ground_truth_base_score.apply(derive_severity_label)

    # ================= BASELINE: direct severity classification =================
    print("\n=== Evaluating baseline (direct severity classification) ===")
    baseline_features = baseline_bundle["vectorizer"].transform(usable_test_df["description"])
    baseline_predicted_encoded = baseline_bundle["model"].predict(baseline_features)
    baseline_predicted_severity = baseline_bundle["label_encoder"].inverse_transform(baseline_predicted_encoded)

    ground_truth_severity_encoded = baseline_bundle["label_encoder"].transform(ground_truth_severity)
    baseline_macro_f1 = f1_score(ground_truth_severity_encoded, baseline_predicted_encoded, average="macro")
    baseline_accuracy = accuracy_score(ground_truth_severity_encoded, baseline_predicted_encoded)
    print(f"Baseline TEST macro-F1: {baseline_macro_f1:.4f}")
    print(f"Baseline TEST accuracy: {baseline_accuracy:.4f}")

    # ================= REFINED: 8-metric prediction -> official formula =================
    print("\n=== Evaluating refined model (8 CVSS Base Metrics -> official formula) ===")
    refined_features = refined_bundle["vectorizer"].transform(usable_test_df["description"])

    per_metric_results = {}
    predicted_metrics_df = pd.DataFrame(index=usable_test_df.index)
    for metric_key in CVSS_METRIC_KEYS:
        model = refined_bundle["per_metric_models"][metric_key]
        encoder = refined_bundle["per_metric_encoders"][metric_key]

        predicted_encoded = model.predict(refined_features)
        predicted_labels = encoder.inverse_transform(predicted_encoded)
        predicted_metrics_df[metric_key] = predicted_labels

        ground_truth_encoded = encoder.transform(ground_truth_metrics[metric_key])
        macro_f1 = f1_score(ground_truth_encoded, predicted_encoded, average="macro")
        accuracy = accuracy_score(ground_truth_encoded, predicted_encoded)
        per_metric_results[metric_key] = {"macro_f1": macro_f1, "accuracy": accuracy}
        print(f"  {metric_key}: TEST macro-F1={macro_f1:.4f}, accuracy={accuracy:.4f}")

    exact_vector_match = (predicted_metrics_df[CVSS_METRIC_KEYS].values == ground_truth_metrics[CVSS_METRIC_KEYS].values).all(axis=1)
    exact_vector_accuracy = exact_vector_match.mean()
    print(f"\nExact 8-metric-vector accuracy (all 8 correct simultaneously): {exact_vector_accuracy:.4f}")

    # Base Score / severity ALWAYS derived from the official formula applied to
    # the predicted metrics -- never predicted directly by any model.
    computed_scores = []
    for _, row in predicted_metrics_df.iterrows():
        result = compute_base_score(CvssVector(
            attack_vector=row["AV"], attack_complexity=row["AC"], privileges_required=row["PR"],
            user_interaction=row["UI"], scope=row["S"], confidentiality=row["C"],
            integrity=row["I"], availability=row["A"],
        ))
        computed_scores.append(result["base_score"])
    predicted_base_score = pd.Series(computed_scores, index=usable_test_df.index)
    predicted_severity = predicted_base_score.apply(derive_severity_label)

    refined_mae = mean_absolute_error(ground_truth_base_score, predicted_base_score)
    refined_severity_accuracy = accuracy_score(ground_truth_severity, predicted_severity)
    refined_severity_macro_f1 = f1_score(ground_truth_severity, predicted_severity, average="macro")

    print(f"\nDerived-severity accuracy (via formula, not direct prediction): {refined_severity_accuracy:.4f}")
    print(f"Derived-severity macro-F1: {refined_severity_macro_f1:.4f}")
    print(f"Base Score MAE: {refined_mae:.4f}")

    # ================= Save results (ground truth and predictions kept as separate columns) =================
    results_df = usable_test_df[["cve_id"] + CVSS_METRIC_KEYS + ["nvd_base_score", "nvd_severity"]].copy()
    results_df = results_df.rename(columns={m: f"ground_truth_{m}" for m in CVSS_METRIC_KEYS})
    for metric_key in CVSS_METRIC_KEYS:
        results_df[f"predicted_{metric_key}"] = predicted_metrics_df[metric_key].values
    results_df["predicted_base_score"] = predicted_base_score.values
    results_df["predicted_severity"] = predicted_severity.values
    results_df["baseline_predicted_severity"] = baseline_predicted_severity

    results_df.to_csv("final_test_evaluation_results.csv", index=False)

    summary = {
        "test_set_size": len(usable_test_df),
        "excluded_unusable_records": int(unusable_mask.sum()),
        "baseline_macro_f1": baseline_macro_f1,
        "baseline_accuracy": baseline_accuracy,
        "refined_per_metric": per_metric_results,
        "refined_exact_vector_accuracy": exact_vector_accuracy,
        "refined_derived_severity_accuracy": refined_severity_accuracy,
        "refined_derived_severity_macro_f1": refined_severity_macro_f1,
        "refined_base_score_mae": refined_mae,
    }
    import json
    with open("final_test_evaluation_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved final_test_evaluation_results.csv and final_test_evaluation_summary.json")


if __name__ == "__main__":
    main()
