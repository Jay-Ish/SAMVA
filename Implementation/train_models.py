"""
Train/validation/test split, and BOTH the baseline (direct severity
classification) and refined (8-metric CVSS prediction) models, trained on
the SAME split of the SAME dataset.

This is deliberate: comparing the refined model against a baseline trained
on mid-term's old ~59-79 record scenario-specific dataset would confound
"8-metric vs direct prediction" with "89k records vs 79 records" -- two
different questions answered as if they were one. Both models below see
identical training data, identical validation data, and are scored on the
identical, untouched test set. The only difference between them is what
they are asked to predict.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, accuracy_score
import joblib

RANDOM_SEED = 42
CVSS_METRIC_COLUMNS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def make_split(df: pd.DataFrame):
    """
    Random 70/15/15 split, seed 42, as locked in the methodology.
    Splitting is done once here and reused identically for both models --
    this is what makes the later comparison fair.
    """
    train_df, temp_df = train_test_split(df, test_size=0.30, random_state=RANDOM_SEED)
    validation_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=RANDOM_SEED)
    print(f"Split sizes -- train: {len(train_df)}, validation: {len(validation_df)}, test: {len(test_df)}")
    return train_df, validation_df, test_df


def derive_severity_label(base_score: float) -> str:
    """Matches the official CVSS v3.1 severity bands, same as cvss_v31.py's _severity()."""
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


def train_baseline_direct_severity_model(train_df, validation_df):
    """
    THE BASELINE: predicts severity CLASS directly from text, matching
    mid-term's original approach -- but retrained here on the same 70% split
    as the refined model, not mid-term's old small dataset. This is the fix
    that makes the later comparison methodologically valid.
    """
    print("\n=== Training baseline (direct severity classification) ===")
    train_labels = train_df["nvd_base_score"].apply(derive_severity_label)

    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2))
    train_features = vectorizer.fit_transform(train_df["description"])

    label_encoder = LabelEncoder()
    train_labels_encoded = label_encoder.fit_transform(train_labels)

    model = RandomForestClassifier(
        n_estimators=250, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1, max_depth=None
    )
    model.fit(train_features, train_labels_encoded)

    validation_features = vectorizer.transform(validation_df["description"])
    validation_labels = validation_df["nvd_base_score"].apply(derive_severity_label)
    validation_labels_encoded = label_encoder.transform(validation_labels)
    validation_predictions = model.predict(validation_features)

    macro_f1 = f1_score(validation_labels_encoded, validation_predictions, average="macro")
    accuracy = accuracy_score(validation_labels_encoded, validation_predictions)
    print(f"Baseline validation macro-F1: {macro_f1:.4f}, accuracy: {accuracy:.4f}")

    return {"vectorizer": vectorizer, "model": model, "label_encoder": label_encoder}


def train_refined_eight_metric_model(train_df, validation_df):
    """
    NOTE: this function is not used by the actual training run below (see
    __main__) -- it predates the checkpoint/resume version, which trains one
    metric at a time so each fits within a single run on this machine. It is
    kept only as a compact reference for what the checkpointed loop does,
    with settings corrected to match what the checkpointed loop actually
    uses (250 trees, max_depth=None, n_jobs=-1, unigrams+bigrams) so this
    docstring/code can never contradict the models actually saved to disk.
    These settings were chosen via tune_hyperparameters.py, comparing a
    small, targeted grid on validation data only (never the test set) --
    see tuning_results.json for the full comparison.
    """
    print("\n=== Training refined model (8 CVSS Base Metrics) ===")
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2))
    train_features = vectorizer.fit_transform(train_df["description"])
    validation_features = vectorizer.transform(validation_df["description"])

    per_metric_models = {}
    per_metric_encoders = {}
    validation_macro_f1_scores = {}

    for metric_name in CVSS_METRIC_COLUMNS:
        label_encoder = LabelEncoder()
        train_labels_encoded = label_encoder.fit_transform(train_df[metric_name])

        model = RandomForestClassifier(
            n_estimators=250, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1, max_depth=None
        )
        model.fit(train_features, train_labels_encoded)

        validation_labels_encoded = label_encoder.transform(validation_df[metric_name])
        validation_predictions = model.predict(validation_features)
        macro_f1 = f1_score(validation_labels_encoded, validation_predictions, average="macro")
        validation_macro_f1_scores[metric_name] = macro_f1
        print(f"  {metric_name}: validation macro-F1 = {macro_f1:.4f}")

        per_metric_models[metric_name] = model
        per_metric_encoders[metric_name] = label_encoder

    return {
        "vectorizer": vectorizer,
        "per_metric_models": per_metric_models,
        "per_metric_encoders": per_metric_encoders,
        "validation_macro_f1_scores": validation_macro_f1_scores,
    }


# NOTE: the CVSS-vector fallback logic (which source is used, and what gets
# recorded as provenance) now lives in resolve_cvss.py as the single source
# of truth. It replaces an earlier version of this file that both (a)
# preserved individual NVD metrics field-by-field, and (b) predicted only
# the missing fields. That approach is no longer used: when the authoritative
# CVSS v3.1 vector is incomplete or invalid, SAMVA predicts all eight Base
# Metrics from the enriched vulnerability text, to keep every final vector's
# provenance unambiguous. See resolve_cvss.py for the actual implementation.


if __name__ == "__main__":
    import os
    import json

    # Load the ALREADY-SPLIT files directly (produced once, at the start of this
    # project, with seed 42) rather than re-splitting from the original combined
    # dataset -- train_set_used.csv / validation_set_clean.csv / test_set_held_out.csv
    # are the exact same split every time, just saved so it never needs repeating.
    train_df = pd.read_csv("train_set_used.csv")
    validation_df = pd.read_csv("validation_set_clean.csv")
    print(f"Loaded pre-split data -- train: {len(train_df)}, validation: {len(validation_df)}")
    print("(test_set_held_out.csv is untouched here -- only evaluate_final.py opens it.)")

    progress_path = "training_progress.json"
    progress = json.load(open(progress_path)) if os.path.exists(progress_path) else {}

    if "baseline" not in progress:
        baseline_bundle = train_baseline_direct_severity_model(train_df, validation_df)
        joblib.dump(baseline_bundle, "baseline_model_frozen.joblib")
        progress["baseline"] = {"done": True}
        json.dump(progress, open(progress_path, "w"))
        print("Baseline trained and saved.")
    else:
        print("Baseline already trained, skipping.")

    vectorizer_path = "refined_vectorizer.joblib"
    if not os.path.exists(vectorizer_path):
        vectorizer = TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2))
        vectorizer.fit(train_df["description"])
        joblib.dump(vectorizer, vectorizer_path)
    else:
        vectorizer = joblib.load(vectorizer_path)

    train_features = vectorizer.transform(train_df["description"])
    validation_features = vectorizer.transform(validation_df["description"])

    for metric_name in CVSS_METRIC_COLUMNS:
        if metric_name in progress:
            print(f"{metric_name} already trained, skipping.")
            continue

        print(f"\nTraining {metric_name}...")
        label_encoder = LabelEncoder()
        train_labels_encoded = label_encoder.fit_transform(train_df[metric_name])

        model = RandomForestClassifier(
            n_estimators=250, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1, max_depth=None
        )
        model.fit(train_features, train_labels_encoded)

        validation_labels_encoded = label_encoder.transform(validation_df[metric_name])
        validation_predictions = model.predict(validation_features)
        macro_f1 = f1_score(validation_labels_encoded, validation_predictions, average="macro")
        print(f"  {metric_name}: validation macro-F1 = {macro_f1:.4f}")

        joblib.dump({"model": model, "encoder": label_encoder}, f"metric_model_{metric_name}.joblib")
        progress[metric_name] = {"validation_macro_f1": macro_f1}
        json.dump(progress, open(progress_path, "w"))

    if all(m in progress for m in CVSS_METRIC_COLUMNS):
        print("\nAll 8 metric models trained. Assembling final refined_model_frozen.joblib...")
        refined_bundle = {
            "vectorizer": vectorizer,
            "per_metric_models": {m: joblib.load(f"metric_model_{m}.joblib")["model"] for m in CVSS_METRIC_COLUMNS},
            "per_metric_encoders": {m: joblib.load(f"metric_model_{m}.joblib")["encoder"] for m in CVSS_METRIC_COLUMNS},
            "validation_macro_f1_scores": {m: progress[m]["validation_macro_f1"] for m in CVSS_METRIC_COLUMNS},
        }
        joblib.dump(refined_bundle, "refined_model_frozen.joblib")
        print("Both models frozen and saved. Test set held out, untouched, ready for final evaluation.")
    else:
        remaining = [m for m in CVSS_METRIC_COLUMNS if m not in progress]
        print(f"\nRun this script again to continue -- still need: {remaining}")
