# SAMVA: A self-adaptive Analysis phase framework in MAPE-K for Vulnerability Assessment. 

This repository contains two folders which is a Literature Review folder, which includes the replication package for the SAMVA systematic literature review, and an implementation folder, which contains the complete, working SAMVA framework, every phase of the architecture, the trained model the evaluation scripts, and the real results across three real-world application scenarios.


## Contents in Literature Review Folder:
- Replication Package: 
- This package has four Columns: Paper Name, RQ1 Finding, RQ2 Finding, and RQ3 Finding.

## Contents in Implementation Folder:
- Full pipeline code for all five phases of the SAMVA architecture (Scanning, Enrichment, Severity Scoring with ML fallback, CWE-Aware Priority Adjustment, and Temporal Reassessment), refer the folder's own README for the exact file-to-phase mapping.
- Evaluation scripts for all six metrics (M1–M6) used to assess SAMVA's accuracy, ranking quality, CWE mapping, enrichment coverage, and temporal responsiveness.
- Model training pipeline such as the scripts used to fetch NVD training data, deduplicate it, and train the frozen CVSS-metric prediction model.
- A training-data leakage checker, used to confirm that the model was genuinely tested on unseen vulnerabilities in each scenario.
- A full README inside the folder with step-by-step setup, run, and reproduction instructions.
