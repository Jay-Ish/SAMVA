"""
Historical EPSS fetcher for M6. RUN ON YOUR OWN MACHINE.

Usage:
    python3 fetch_epss_historical.py trivy_scenario1.json epss_historical_scenario1.json
    python3 fetch_epss_historical.py trivy_scenario2.json epss_historical_scenario2.json
    python3 fetch_epss_historical.py trivy_scenario3.json epss_historical_scenario3.json
"""
import json, sys, time, urllib.request, urllib.error
from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2

API_BASE = "https://api.first.org/data/v1/epss"
DATE_EARLY = "2025-08-06"
DATE_LATE = "2026-08-05"


def fetch_at_date(cve_ids, date_str):
    url = f"{API_BASE}?cve={','.join(cve_ids)}&date={date_str}"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return {row["cve"]: float(row["epss"]) for row in data.get("data", [])}
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  WARNING: {e}")
        return {}


if __name__ == "__main__":
    trivy_input_file = sys.argv[1] if len(sys.argv) > 1 else "trivy_scenario1.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "epss_historical_lookup.json"

    print(f"Input: {trivy_input_file}")
    print(f"Output: {output_file}")
    print(f"Comparing {DATE_EARLY} -> {DATE_LATE}")

    raw = load_trivy_findings(trivy_input_file)
    enriched, _ = run_phase2(raw)
    cve_ids = sorted(set(e["cve_id"] for e in enriched if e["cve_id_resolved"]))
    print(f"Found {len(cve_ids)} unique resolved CVE IDs.")

    early, late = {}, {}
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i+100]
        early.update(fetch_at_date(batch, DATE_EARLY))
        time.sleep(1)
        late.update(fetch_at_date(batch, DATE_LATE))
        time.sleep(1)

    combined = {}
    for cve in set(early) | set(late):
        if cve in early and cve in late:
            combined[cve] = {"date_early": {"date": DATE_EARLY, "epss": early[cve]},
                              "date_late": {"date": DATE_LATE, "epss": late[cve]}}

    with open(output_file, "w") as f:
        json.dump(combined, f, indent=2)
    print(f"Done. {len(combined)} CVEs with data at both dates. Saved to {output_file}")
