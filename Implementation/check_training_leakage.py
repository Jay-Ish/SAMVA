"""
Training Leakage Check
========================
Checks whether any CVE used to evaluate the model in a scenario also
appears in the model's own training data. If it does, that specific
evaluation record isn't a fair test of generalisation -- the model may
have already seen the correct answer during training.

This matters because the training set covers most of real NVD for
2022-2025, and a scenario's own real dependencies can genuinely include
CVEs from that same window -- so overlap is a real possibility, not
just a theoretical one, and needs to be checked directly rather than
assumed either way.

Usage:
    python3 check_training_leakage.py trivy_scenario1.json
    python3 check_training_leakage.py trivy_scenario2.json
    python3 check_training_leakage.py trivy_scenario3.json
"""

import sys

import pandas as pd

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2

TRAINING_SET_FILE = "train_set_used.csv"
VALIDATION_SET_FILE = "validation_set_clean.csv"
TEST_SET_FILE = "test_set_held_out.csv"


def get_scenario_cve_ids(trivy_input_file):
    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)
    return set(f["cve_id"] for f in enriched_findings if f["cve_id_resolved"])


def get_training_cve_ids():
    """
    Reads the CVE IDs that went into training, validation, and the
    official held-out test set. All three need to be checked separately
    -- overlap with the TEST set specifically would be a more serious
    problem, since that set is meant to represent genuinely unseen data
    for the official evaluate_final.py result too.
    """
    cve_ids_by_split = {}
    for split_name, file_name in [("train", TRAINING_SET_FILE),
                                    ("validation", VALIDATION_SET_FILE),
                                    ("test", TEST_SET_FILE)]:
        try:
            df = pd.read_csv(file_name)
            id_column = "cve_id" if "cve_id" in df.columns else df.columns[0]
            cve_ids_by_split[split_name] = set(df[id_column].astype(str))
        except FileNotFoundError:
            print(f"  NOTE: {file_name} not found -- skipping the {split_name} split check.")
            cve_ids_by_split[split_name] = set()
    return cve_ids_by_split


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"

    scenario_cve_ids = get_scenario_cve_ids(trivy_input_file)
    print(f"Scenario CVEs (unique, real-format only): {len(scenario_cve_ids)}")

    training_cve_ids_by_split = get_training_cve_ids()

    print()
    for split_name, split_cve_ids in training_cve_ids_by_split.items():
        if not split_cve_ids:
            continue
        overlap = scenario_cve_ids & split_cve_ids
        print(f"Overlap with {split_name} split: {len(overlap)} CVE(s)")
        if overlap:
            print(f"  Overlapping CVEs: {sorted(overlap)[:20]}"
                  f"{' ... (truncated)' if len(overlap) > 20 else ''}")

    print()
    total_overlap = set()
    for split_cve_ids in training_cve_ids_by_split.values():
        total_overlap |= (scenario_cve_ids & split_cve_ids)

    if total_overlap:
        overlap_pct = round(100 * len(total_overlap) / len(scenario_cve_ids), 1)
        print(f"TOTAL: {len(total_overlap)} of {len(scenario_cve_ids)} scenario CVEs "
              f"({overlap_pct}%) appear somewhere in the model's training pipeline.")
        print("These specific records should be excluded, or reported separately, "
              "when claiming the scenario result demonstrates genuine generalisation.")
    else:
        print("TOTAL: No overlap found -- every scenario CVE is genuinely unseen by the model.")
