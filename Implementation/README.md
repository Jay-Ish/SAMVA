# SAMVA — Self-Adaptive Analysis-Phase Framework for Vulnerability Assessment

This is the complete implementation for SAMVA's Part B: a machine-learning-assisted
pipeline that fills in missing CVSS scores for real-world vulnerabilities, combines
them with EPSS exploitation data and CWE weakness categories, and produces a
prioritised vulnerability report.

## What SAMVA actually does, in one paragraph

When a vulnerability scanner (Trivy) finds a known issue, it often already has a
severity score. But sometimes it doesn't — a brand-new vulnerability might not be
scored anywhere yet. SAMVA's job is to fill that gap: a trained machine learning
model reads the vulnerability's text description and predicts the 8 official CVSS
metrics (like "how hard is this to exploit"). Those predictions are then run
through the *real, official* CVSS formula — never guessed directly — so every
result stays standard-compliant, whether it came from an authoritative source or
from the model.

## Requirements

- Python 3.9 or newer
- Install the required libraries:
  ```bash
  pip install pandas numpy scikit-learn scipy joblib
  ```
- [Trivy](https://trivy.dev) installed, for scanning applications
- A free NVD API key (optional but recommended — speeds up data fetching a lot):
  https://nvd.nist.gov/developers/request-an-api-key

## Setting up your NVD API key (do this once)

Your API key is never written into any file in this project — it's read from an
environment variable, so it's always safe to push this code to GitHub without
accidentally leaking it.

**On macOS/Linux:**
```bash
export NVD_API_KEY="your-real-key-goes-here"
```

**On Windows (PowerShell):**
```powershell
$env:NVD_API_KEY="your-real-key-goes-here"
```

Do this once per terminal session before running any of the fetch scripts.

## Project files, what each one does

| File | What it does |
|---|---|
| `cvss_v31.py` | The official CVSS v3.1 formula — turns 8 metric values into a final score |
| `config.py` | All the fixed settings (weights, thresholds, the CWE Top 25 list) in one place |
| `phase1_ingest.py` | Reads a raw Trivy scan report |
| `phase2_enrich.py` | Cleans up and deduplicates the raw findings |
| `phase3_score.py` | Works out each finding's CVSS score, from Trivy's cache or NVD |
| `apply_ml_fallback.py` | The machine learning model — predicts CVSS for findings with no score anywhere |
| `cwe_fallback.py` | Assigns a weakness category (CWE) to each finding |
| `phase4_adjust.py` | Adjusts each finding's priority based on how dangerous its CWE category is |
| `compute_m1_m2_scenario.py` | Evaluation: how accurate is the model on this app's own vulnerabilities? |
| `compute_m3.py` | Evaluation: does SAMVA's ranking still make sense compared to plain CVSS? |
| `compute_m4.py` | Evaluation: how accurate is the CWE-guessing fallback? |
| `compute_m5.py` | Evaluation: what percentage of findings got fully enriched? |
| `compute_m6.py` | Evaluation: does SAMVA correctly react when real-world risk changes? |
| `check_training_leakage.py` | Checks whether any scenario CVE was also used to train the model |
| `fetch_nvd_data.py` | Downloads CVSS/CWE data from NVD for a scan's CVEs |
| `fetch_epss.py` | Downloads current EPSS (exploitation likelihood) scores |
| `fetch_epss_historical.py` | Downloads EPSS scores from two past dates, for the M6 check |
| `train_models.py` | Trains the 8 CVSS-metric prediction models from scratch |
| `dedup_dataset.py` | Removes near-duplicate training records before training |
| `evaluate_final.py` | The one-time, official evaluation of the trained model |
| `fetch_nvd_dataset.py` | Downloads the large training dataset from NVD |

## How to run a scenario, start to finish

These steps work identically for all three scenarios — just change the file names.

### Step 1 — Scan the application with Trivy
```bash
git clone https://github.com/GoogleCloudPlatform/microservices-demo.git
trivy fs --scanners vuln,misconfig --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL -f json -o trivy_scenario1.json microservices-demo/
```
(Repeat with the Scenario 2 and 3 repositories, saving to `trivy_scenario2.json`
and `trivy_scenario3.json`.)

### Step 2 — Fetch supporting data (needs internet access)
```bash
python3 fetch_nvd_data.py trivy_scenario1.json nvd_data_lookup_scenario1.json
python3 fetch_epss.py trivy_scenario1.json epss_lookup_scenario1.json
python3 fetch_epss_historical.py trivy_scenario1.json epss_historical_scenario1.json
```

### Step 3 — Make sure the trained model is in this folder
You need `refined_model_frozen.joblib` in the same folder as everything else.
If you don't have it yet, train it once from scratch:
```bash
python3 fetch_nvd_dataset.py
python3 dedup_dataset.py
python3 train_models.py
python3 evaluate_final.py
```
(This step only needs to be done once — the same trained model is reused for
all three scenarios, unchanged.)

### Step 4 — Check for training-data leakage (important, do this before trusting results)
```bash
python3 check_training_leakage.py trivy_scenario1.json
python3 check_training_leakage.py trivy_scenario2.json
python3 check_training_leakage.py trivy_scenario3.json
```
This checks whether any CVE in a scenario also appears in the model's own
training data — if it does, that record isn't a fair test of genuine
generalisation. `compute_m1_m2_scenario.py` automatically excludes any
overlapping CVEs from its evaluation by default.

This step needs `train_set_used.csv`, `validation_set_clean.csv`, and
`test_set_held_out.csv` (produced during Step 3's model training) in this
same folder. If you don't have them, either copy them in from wherever
Step 3 was run, or re-run Step 3 in this folder.

### Step 5 — Run the evaluation metrics
```bash
python3 compute_m1_m2_scenario.py trivy_scenario1.json nvd_data_lookup_scenario1.json
python3 compute_m3.py trivy_scenario1.json nvd_data_lookup_scenario1.json
python3 compute_m4.py trivy_scenario1.json
python3 compute_m5.py trivy_scenario1.json epss_lookup_scenario1.json nvd_data_lookup_scenario1.json
python3 compute_m6.py trivy_scenario1.json epss_historical_scenario1.json nvd_data_lookup_scenario1.json
```

Repeat Steps 2, 4, and 5 for `trivy_scenario2.json` and `trivy_scenario3.json`
(with their own matching output file names) to get results for all three
applications.

### Step 6 — Generate the comparison figures (after all 3 scenarios are done)
```bash
python3 generate_comparison_visualizations.py
```
This produces 8 figures (each saved as both PNG and PDF) plus 9 supporting
CSV tables, covering every evaluation metric with the chart type that
actually fits the data:
- Figure 1: M1, per-metric accuracy heatmap (8 CVSS metrics x 3 scenarios)
- Figure 2: M2, CVSS Base Score MAE, one bar per scenario
- Figure 3: severity before vs. after SAMVA, grouped bar comparison
- Figure 4: final SAMVA-derived severity distribution, one pie chart per scenario
- Figure 5: M3, rank-shift dumbbell plot (CVSS-only rank vs. SAMVA rank per CVE)
- Figure 6: M4, CWE mapping accuracy with 95% confidence intervals
- Figure 7: M5, complete enrichment rate (CVE + CVSS + CWE all present)
- Figure 8: M6, directional accuracy over time (EPSS movement per CVE)

If running inside Jupyter and you want the figures to display inline
(not just save as files), use `%run generate_comparison_visualizations.py`
instead of `!python generate_comparison_visualizations.py` -- running a
script as a separate process (`!python`) never shows plots inside the
notebook, regardless of what the script does.

## A note on evaluation design

Two different kinds of results appear in this project, and they mean different
things:

- **The large NVD test-set result** (from `evaluate_final.py`) is the *primary*
  measure of the model's real accuracy — it's tested on over 11,000 held-out
  records the model never saw during training.
- **The per-scenario results** (from `compute_m1_m2_scenario.py` and friends) are
  *secondary* evidence, showing how the same, unchanged model performs on three
  specific real applications. These samples are much smaller, so they should
  always be read alongside the primary result, not instead of it.

## Reproducing this from a completely clean environment

1. Clone this repository
2. Install the requirements listed above
3. Set your `NVD_API_KEY` environment variable
4. Follow Steps 1–4 above for each scenario

No file in this repository contains any personal information, file paths specific
to one computer, or API keys.
