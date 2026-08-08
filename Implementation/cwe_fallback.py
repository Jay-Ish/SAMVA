"""
SAMVA CWE Fallback -- Weakness Category Lookup
=================================================
Every vulnerability needs a CWE (weakness category) assigned for Phase 4's
priority adjustment. This file finds a CWE using three sources, in order
of trustworthiness:

  1. NVD's own official CVE-to-CWE mapping (most trustworthy).
  2. Trivy's own cached CWE tag, if NVD doesn't have one.
  3. A text-similarity match against the CWE Top 25 category descriptions,
     as a last resort, if neither of the above has anything.
"""

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Short reference descriptions for each CWE Top 25 category, used only for
# the text-similarity fallback match (step 3 above).
CWE_REFERENCE_DESCRIPTIONS = {
    "CWE-79": "cross site scripting xss improper neutralization of input during web page generation script injection",
    "CWE-89": "sql injection improper neutralization of special elements used in an sql command database query injection",
    "CWE-352": "cross site request forgery csrf forces a user to execute unwanted actions on a web application",
    "CWE-862": "missing authorization software does not perform an authorization check when a user attempts to access a resource",
    "CWE-787": "out of bounds write software writes data past the end or before the beginning of the intended buffer memory corruption",
    "CWE-22": "path traversal improper limitation of a pathname to a restricted directory directory traversal file access",
    "CWE-416": "use after free reference to memory after it has been freed dangling pointer memory corruption",
    "CWE-125": "out of bounds read software reads data past the end or before the beginning of the intended buffer",
    "CWE-78": "os command injection improper neutralization of special elements used in an os command shell injection",
    "CWE-94": "code injection improper control of generation of code eval injection remote code execution",
    "CWE-120": "classic buffer overflow copies input buffer without checking size leading to buffer overflow",
    "CWE-434": "unrestricted upload of file with dangerous type allows attacker to upload malicious executable file",
    "CWE-476": "null pointer dereference dereferencing a pointer that is expected to be a valid value but is null crash",
    "CWE-121": "stack based buffer overflow stack overflow condition writing outside the bounds of a stack allocated buffer",
    "CWE-502": "deserialization of untrusted data application deserializes untrusted data without verifying resulting object",
    "CWE-122": "heap based buffer overflow overflow condition writing outside the bounds of a heap allocated buffer",
    "CWE-863": "incorrect authorization software performs authorization check but the check is incorrect access control",
    "CWE-20": "improper input validation software does not validate or incorrectly validates input before use",
    "CWE-284": "improper access control software does not restrict access to a resource from an unauthorized actor",
    "CWE-200": "exposure of sensitive information to an unauthorized actor information disclosure data leak",
    "CWE-306": "missing authentication for critical function software does not perform authentication for functionality",
    "CWE-918": "server side request forgery ssrf web application fetches remote resource without validating user supplied url",
    "CWE-77": "command injection improper neutralization of special elements used in a command shell metacharacters",
    "CWE-639": "authorization bypass through user controlled key uses a key to control access without verifying authorization",
    "CWE-770": "allocation of resources without limits or throttling denial of service uncontrolled resource consumption",
}

MINIMUM_SIMILARITY_TO_ACCEPT_A_MATCH = 0.12  # deliberately conservative -- only match if genuinely similar

# These get built once, the first time they're needed, and reused after that.
_text_vectorizer = None
_reference_text_matrix = None
_reference_cwe_id_list = None


def _build_reference_index():
    """Prepares the CWE Top 25 reference descriptions for similarity matching."""
    global _text_vectorizer, _reference_text_matrix, _reference_cwe_id_list
    _reference_cwe_id_list = list(CWE_REFERENCE_DESCRIPTIONS.keys())
    reference_texts = list(CWE_REFERENCE_DESCRIPTIONS.values())
    _text_vectorizer = TfidfVectorizer(stop_words="english")
    _reference_text_matrix = _text_vectorizer.fit_transform(reference_texts)


def match_cwe_by_similarity(description_text):
    """
    Compares a vulnerability's description against the CWE Top 25
    reference descriptions and returns the closest match, or (None, score)
    if nothing is similar enough to trust.
    """
    if _text_vectorizer is None:
        _build_reference_index()
    if not description_text:
        return None, 0.0

    description_vector = _text_vectorizer.transform([description_text])
    similarity_scores = cosine_similarity(description_vector, _reference_text_matrix)[0]
    best_match_index = similarity_scores.argmax()
    best_match_score = similarity_scores[best_match_index]

    if best_match_score >= MINIMUM_SIMILARITY_TO_ACCEPT_A_MATCH:
        return _reference_cwe_id_list[best_match_index], round(float(best_match_score), 4)
    return None, round(float(best_match_score), 4)


def apply_cwe_fallback(records, nvd_data_lookup=None):
    """
    Assigns a CWE to every record, using the 3-source priority order:
    NVD's official mapping first, then Trivy's own cached tag, then the
    text-similarity fallback as a last resort. The 'cwe_source' field on
    each record shows exactly which source was used.
    """
    nvd_data_lookup = nvd_data_lookup or {}
    updated_records = []

    for record in records:
        record = dict(record)
        nvd_entry = nvd_data_lookup.get(record.get("cve_id"))
        nvd_cwe_list = nvd_entry["cwe_ids"] if nvd_entry and nvd_entry.get("cwe_ids") else []

        if nvd_cwe_list:
            record["cwe_ids"] = nvd_cwe_list
            record["cwe_source"] = "nvd_primary"
        elif record.get("cwe_ids"):
            record["cwe_source"] = "trivy_cached"
        else:
            matched_cwe_id, similarity_score = match_cwe_by_similarity(record.get("description"))
            if matched_cwe_id:
                record["cwe_ids"] = [matched_cwe_id]
                record["cwe_source"] = "tfidf_fallback"
                record["cwe_fallback_similarity"] = similarity_score
            else:
                record["cwe_source"] = "unmapped"
                record["cwe_fallback_similarity"] = similarity_score

        updated_records.append(record)

    return updated_records


if __name__ == "__main__":
    import sys
    import json
    import os
    from phase1_ingest import load_trivy_findings
    from phase2_enrich import run_phase2

    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    raw_findings = load_trivy_findings(trivy_file)
    enriched_findings, _ = run_phase2(raw_findings)

    nvd_lookup = {}
    nvd_lookup_file = sys.argv[2] if len(sys.argv) > 2 else "nvd_data_lookup.json"
    if os.path.exists(nvd_lookup_file):
        with open(nvd_lookup_file) as f:
            nvd_lookup = json.load(f)

    filled_findings = apply_cwe_fallback(enriched_findings, nvd_lookup)
    source_counts = {}
    for finding in filled_findings:
        source_counts[finding["cwe_source"]] = source_counts.get(finding["cwe_source"], 0) + 1
    print("CWE source breakdown:", source_counts)
