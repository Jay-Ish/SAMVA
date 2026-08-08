"""
Fetch NVD Data -- CVSS Gap-Fill and CWE Lookup
=================================================
Queries the National Vulnerability Database (NVD) directly for every
unique CVE in a scan, to (a) fill in a CVSS score if Trivy's own cache
doesn't have one, and (b) get the official CWE weakness category.

RUN THIS ON YOUR OWN MACHINE (needs internet access).

--- About the API key ---
An NVD API key is optional but strongly recommended -- without one, NVD
limits requests to 5 per 30 seconds (slow for large scans); with a free
key, that jumps to 50 per 30 seconds. Get a free key at:
https://nvd.nist.gov/developers/request-an-api-key

This script reads your API key from an ENVIRONMENT VARIABLE, never from
a line of code. This means your real key is NEVER written into this file
and can never accidentally be uploaded to GitHub, even if you forget to
remove it before pushing.

Before running, set your key in the terminal (only needs doing once per
terminal session):

    export NVD_API_KEY="your-real-key-goes-here"

Usage:
    python3 fetch_nvd_data.py trivy_scenario1.json nvd_data_lookup_scenario1.json
    python3 fetch_nvd_data.py trivy_scenario2.json nvd_data_lookup_scenario2.json
    python3 fetch_nvd_data.py trivy_scenario3.json nvd_data_lookup_scenario3.json
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Reads the API key from the environment -- this is None if you haven't
# set it, and the script still works fine without one, just more slowly.
NVD_API_KEY = os.environ.get("NVD_API_KEY")


def fetch_one_cve_from_nvd(cve_id):
    """
    Asks NVD for one CVE's data and returns the CVSS vector and CWE list,
    or None if NVD doesn't have a record for this CVE.
    """
    request_url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
    request = urllib.request.Request(request_url)
    if NVD_API_KEY:
        request.add_header("apiKey", NVD_API_KEY)

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response_data = json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError) as error:
        print(f"  WARNING: {cve_id} failed ({error})")
        return None

    vulnerabilities = response_data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve_data = vulnerabilities[0].get("cve", {})

    cvss_vector = None
    metrics = cve_data.get("metrics", {})
    for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
        if metric_key in metrics and metrics[metric_key]:
            cvss_vector = metrics[metric_key][0]["cvssData"].get("vectorString")
            break

    cwe_ids_found = []
    for weakness_entry in cve_data.get("weaknesses", []):
        for description_entry in weakness_entry.get("description", []):
            value = description_entry.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids_found.append(value)

    return {"cvss_vector": cvss_vector, "cwe_ids": sorted(set(cwe_ids_found))}


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "nvd_data_lookup.json"

    if NVD_API_KEY:
        print("Using your NVD API key (found in the NVD_API_KEY environment variable).")
    else:
        print("No NVD_API_KEY environment variable set -- this will be slower.")
        print('To speed this up: export NVD_API_KEY="your-key-here"')

    print(f"Input: {trivy_input_file}")
    print(f"Output: {output_file}")

    raw_findings = load_trivy_findings(trivy_input_file)
    enriched_findings, _ = run_phase2(raw_findings)
    unique_cve_ids = sorted(set(f["cve_id"] for f in enriched_findings if f["cve_id_resolved"]))
    print(f"Found {len(unique_cve_ids)} unique resolved CVEs.")

    seconds_between_requests = 0.6 if NVD_API_KEY else 6
    estimated_minutes = round(len(unique_cve_ids) * seconds_between_requests / 60, 1)
    print(f"Estimated time: ~{estimated_minutes} minutes")

    results_lookup_table = {}
    for index, cve_id in enumerate(unique_cve_ids, 1):
        print(f"  [{index}/{len(unique_cve_ids)}] {cve_id}...")
        record = fetch_one_cve_from_nvd(cve_id)
        if record:
            results_lookup_table[cve_id] = record
        time.sleep(seconds_between_requests)

    with open(output_file, "w") as f:
        json.dump(results_lookup_table, f, indent=2)

    print(f"Done. {len(results_lookup_table)}/{len(unique_cve_ids)} resolved. Saved to {output_file}")
