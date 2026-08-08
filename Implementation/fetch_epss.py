"""
Fetches EPSS scores. RUN ON YOUR OWN MACHINE (needs internet to api.first.org).

Usage:
    python3 fetch_epss.py trivy_scenario1.json epss_lookup_scenario1.json
    python3 fetch_epss.py trivy_scenario2.json epss_lookup_scenario2.json
    python3 fetch_epss.py trivy_scenario3.json epss_lookup_scenario3.json
"""
import json, sys, time, urllib.request, urllib.error
from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2

API_BASE = "https://api.first.org/data/v1/epss"


def fetch_epss_batch(cve_ids):
    """Asks FIRST's EPSS API for a batch of up to 100 CVEs at once and
    returns a dictionary mapping each CVE ID to its current EPSS score."""
    url = f"{API_BASE}?cve={','.join(cve_ids)}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return {row["cve"]: float(row["epss"]) for row in data.get("data", [])}
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  WARNING: {e}")
        return {}


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "epss_lookup.json"

    print(f"Input: {trivy_input_file}")
    print(f"Output: {output_file}")

    raw = load_trivy_findings(trivy_input_file)
    enriched, _ = run_phase2(raw)
    cve_ids = sorted(set(e["cve_id"] for e in enriched if e["cve_id_resolved"]))
    print(f"Found {len(cve_ids)} unique resolved CVE IDs.")

    lookup = {}
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i+100]
        print(f"Fetching {len(batch)} CVEs ({i+1}-{i+len(batch)} of {len(cve_ids)})...")
        lookup.update(fetch_epss_batch(batch))
        time.sleep(1)

    with open(output_file, "w") as f:
        json.dump(lookup, f, indent=2)
    print(f"Done. {len(lookup)}/{len(cve_ids)} CVEs. Saved to {output_file}")
