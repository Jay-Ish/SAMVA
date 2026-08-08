"""
SAMVA Configuration
====================
All the fixed, "locked" settings used throughout the SAMVA pipeline live
here in one place. If you need to change a weight or threshold, change it
here rather than hunting through other files.
"""

# --- SAMVA Composite Severity Score (SCSS) weights ---
# SCSS combines three signals: how bad the vulnerability's impact is,
# how easy it is to exploit, and how likely it is to actually be
# exploited in the real world (EPSS). These three weights must add up to 1.0.
IMPACT_WEIGHT = 0.35
EXPLOITABILITY_WEIGHT = 0.35
EPSS_WEIGHT = 0.30
assert abs(IMPACT_WEIGHT + EXPLOITABILITY_WEIGHT + EPSS_WEIGHT - 1.0) < 1e-9

# --- The exact maximum values Impact and Exploitability can reach ---
# These are used to rescale both onto a 0-1 range before combining them.
# Verified by testing the CVSS v3.1 formula at its real boundary conditions
# (NOT the same as the formula's internal coefficients, which are 6.42/8.22).
IMPACT_MAXIMUM_VALUE = 6.0477
EXPLOITABILITY_MAXIMUM_VALUE = 3.8870

# --- CWE Top 25 weighting (Section 3.5) ---
# Source: CISA/MITRE 2025 CWE Top 25 Most Dangerous Software Weaknesses
# (https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
# A vulnerability whose weakness type is in the Top 10 gets a bigger
# priority boost than one in ranks 11-25; anything not on the list is
# treated as neutral (no boost, no penalty).
CWE_TOP_10_WEAKNESS_IDS = {
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
    "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
}
CWE_RANKS_11_TO_25_WEAKNESS_IDS = {
    "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
    "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
    "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770",
}
CWE_TOP_10_SCORE_MULTIPLIER = 1.15
CWE_RANKS_11_TO_25_SCORE_MULTIPLIER = 1.08
CWE_NOT_RANKED_SCORE_MULTIPLIER = 1.00

# --- Threshold for deciding whether EPSS movement is "real" (Section 4.1.3, M6) ---
# If a vulnerability's EPSS score changes by less than this amount between
# two dates, it is treated as noise, not a genuine risk change.
EPSS_MEANINGFUL_CHANGE_THRESHOLD = 0.02

# --- Official CVSS v3.1 metric weight tables (FIRST.org specification) ---
# Used to recompute Impact and Exploitability from a full CVSS vector string.
ATTACK_VECTOR_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
ATTACK_COMPLEXITY_WEIGHTS = {"L": 0.77, "H": 0.44}
USER_INTERACTION_WEIGHTS = {"N": 0.85, "R": 0.62}
PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PRIVILEGES_REQUIRED_WEIGHTS_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
IMPACT_METRIC_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}
