"""
SAMVA M4 -- CWE Mapping Accuracy
==================================
Checks how accurately the text-similarity fallback (see cwe_fallback.py)
can guess a vulnerability's weakness category from its description alone,
by hiding known CWE labels and seeing if the fallback can recover them.

Only tested on vulnerabilities whose real CWE is one of the Top 25
categories, since those are the only categories the fallback can
possibly guess against.

Works identically for all three scenarios.

Usage:
    python3 compute_m4.py trivy_scenario1.json
    python3 compute_m4.py trivy_scenario2.json
    python3 compute_m4.py trivy_scenario3.json
"""

import json
import sys

from sklearn.model_selection import train_test_split

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from cwe_fallback import CWE_REFERENCE_DESCRIPTIONS, match_cwe_by_similarity, _build_reference_index


def run_m4_evaluation(trivy_input_file="trivy_scenario1.json", test_size=0.25, random_state=42):
    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)

    top_25_cwe_ids = set(CWE_REFERENCE_DESCRIPTIONS.keys())
    seen_cve_ids = set()
    ground_truth_records = []
    for finding in enriched_findings:
        has_top25_cwe = finding["cwe_ids"] and any(cwe_id in top_25_cwe_ids for cwe_id in finding["cwe_ids"])
        if has_top25_cwe and finding["cve_id"] not in seen_cve_ids:
            ground_truth_records.append(finding)
            seen_cve_ids.add(finding["cve_id"])

    if len(ground_truth_records) < 10:
        return {"error": f"Only {len(ground_truth_records)} eligible records -- too few for a meaningful test."}

    descriptions = [record["description"] for record in ground_truth_records]
    true_cwe_ids = [next(c for c in record["cwe_ids"] if c in top_25_cwe_ids) for record in ground_truth_records]

    _, test_descriptions, _, test_true_cwe_ids = train_test_split(
        descriptions, true_cwe_ids, test_size=test_size, random_state=random_state
    )

    _build_reference_index()

    correct_count = 0
    example_predictions = []
    for description, true_cwe_id in zip(test_descriptions, test_true_cwe_ids):
        predicted_cwe_id, similarity_score = match_cwe_by_similarity(description)
        is_correct = predicted_cwe_id == true_cwe_id
        correct_count += int(is_correct)
        example_predictions.append({
            "true": true_cwe_id, "predicted": predicted_cwe_id,
            "similarity": similarity_score, "correct": is_correct,
        })

    accuracy = correct_count / len(test_true_cwe_ids) if test_true_cwe_ids else 0.0

    return {
        "M4_cwe_mapping_accuracy_pct": round(accuracy * 100, 2),
        "test_set_size": len(test_true_cwe_ids),
        "eligible_ground_truth_records": len(ground_truth_records),
        "sample_predictions": example_predictions[:5],
    }


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    print(json.dumps(run_m4_evaluation(trivy_input_file), indent=2))
