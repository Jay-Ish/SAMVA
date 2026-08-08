"""
Real NVD API 2.0 client for building the SAMVA training dataset.

Run this ON YOUR OWN MACHINE (not in a sandboxed environment) so it has
unrestricted internet access to services.nvd.nist.gov.

Usage:
    python3 fetch_nvd_dataset.py --start 2023-01-01 --end 2024-12-31 --out nvd_dataset.csv
    python3 fetch_nvd_dataset.py --start 2023-01-01 --end 2024-12-31 --out nvd_dataset.csv --api-key YOUR_KEY_HERE

Get a free API key (raises rate limit from 5 to 50 requests/30s):
    https://nvd.nist.gov/developers/request-an-api-key

Notes on correctness (read before running):
- The NVD API limits each request to a 120-day publish-date window, so this
  script chunks the requested date range automatically.
- Without an API key you get 5 requests / 30s; WITH one, 50 requests / 30s.
  The script sleeps accordingly -- do not remove the delay or you will be
  rate-limited (HTTP 403) partway through.
- Vector-string parsing splits on "/" first, then "KEY:VALUE" -- NOT naive
  substring search -- because "CVSS:" contains "S:" and "AC:" contains "C:",
  which silently corrupts naive parsing (this exact bug was caught and fixed
  during this project's development; see build_dataset.py for the writeup).
"""

import argparse
import csv
import sys
import time
from datetime import datetime, timedelta

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = 120          # NVD's hard limit per request
RESULTS_PER_PAGE = 2000    # NVD's max


def daterange_chunks(start: datetime, end: datetime, days: int):
    cur = start
    while cur < end:
        chunk_end = min(cur + timedelta(days=days), end)
        yield cur, chunk_end
        cur = chunk_end


def parse_cve(item: dict) -> dict | None:
    cve = item["cve"]
    english_description = next((entry["value"] for entry in cve.get("descriptions", []) if entry["lang"] == "en"), None)
    if not english_description:
        return None

    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
    if not metrics:
        return None
    primary = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
    cvss_data = primary["cvssData"]

    # Correct parser: split on "/" into tokens first, THEN look up keys.
    # (Naive str.split("S:") or str.split("C:") breaks because "CVSS:" contains
    # "S:" and "AC:" contains "C:" -- verified bug, see project notes.)
    vector_string = cvss_data["vectorString"]
    metric_tokens = dict(tok.split(":", 1) for tok in vector_string.split("/") if ":" in tok)

    cwe = None
    for w in cve.get("weaknesses", []):
        for weakness_description in w.get("description", []):
            if weakness_description.get("lang") == "en" and weakness_description["value"].startswith("CWE-"):
                cwe = weakness_description["value"]
                break
        if cwe:
            break

    return {
        "cve_id": cve["id"],
        "description": english_description,
        "AV": metric_tokens.get("AV"), "AC": metric_tokens.get("AC"), "PR": metric_tokens.get("PR"),
        "UI": metric_tokens.get("UI"), "S": metric_tokens.get("S"), "C": metric_tokens.get("C"),
        "I": metric_tokens.get("I"), "A": metric_tokens.get("A"),
        "nvd_base_score": cvss_data["baseScore"],
        "nvd_severity": cvss_data["baseSeverity"],
        "cwe": cwe,
        "vuln_status": cve.get("vulnStatus"),
    }


def fetch_range(start: datetime, end: datetime, api_key: str | None, delay: float):
    headers = {"apiKey": api_key} if api_key else {}
    start_index = 0
    total = None
    while total is None or start_index < total:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT00:00:00.000"),
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
            "noRejected": "",  # exclude REJECT/Rejected status server-side
        }
        resp = requests.get(API_URL, params=params, headers=headers, timeout=30)
        if resp.status_code == 403:
            print(f"  Rate limited at index {start_index}, backing off 30s...", file=sys.stderr)
            time.sleep(30)
            continue
        resp.raise_for_status()
        data = resp.json()
        total = data["totalResults"]
        for item in data.get("vulnerabilities", []):
            parsed_record = parse_cve(item)
            if parsed_record:
                yield parsed_record
        start_index += RESULTS_PER_PAGE
        print(f"  {start.date()} to {end.date()}: {min(start_index, total)}/{total}", file=sys.stderr)
        time.sleep(delay)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="YYYY-MM-DD")
    ap.add_argument("--end", required=True, help="YYYY-MM-DD")
    ap.add_argument("--out", required=True)
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    delay = 0.7 if args.api_key else 6.5  # stay safely under 50/30s or 5/30s
    start = datetime.strptime(args.start, "%Y-%m-%d")
    end = datetime.strptime(args.end, "%Y-%m-%d")

    fieldnames = ["cve_id", "description", "AV", "AC", "PR", "UI", "S", "C", "I", "A",
                  "nvd_base_score", "nvd_severity", "cwe", "vuln_status"]

    seen_cve_ids = set()
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for chunk_start, chunk_end in daterange_chunks(start, end, WINDOW_DAYS):
            print(f"Fetching {chunk_start.date()} -> {chunk_end.date()}...", file=sys.stderr)
            for cve_record in fetch_range(chunk_start, chunk_end, args.api_key, delay):
                if cve_record["cve_id"] in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_record["cve_id"])
                writer.writerow(cve_record)

    print(f"\nDone. {len(seen_cve_ids)} unique CVE records with CVSS v3.1 written to {args.out}")


if __name__ == "__main__":
    main()
