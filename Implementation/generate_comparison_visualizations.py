"""
SAMVA Report Figures -- Final Refinement
===========================================
Produces 8 report figures (7 formal + 1 supporting severity comparison,
plus a supporting severity-distribution pie chart) and their underlying
CSV tables.

Figures are saved as PDF (vector -- scales to any width in LaTeX with
zero quality loss, so this is what actually goes into the IEEE report)
and PNG (for quick on-screen review). Sized generously for on-screen
clarity; PDF vector export means LaTeX can still place them at exact
IEEE column widths without any loss of sharpness -- the two goals
(readable now, correctly sized in the final paper) are not in tension,
since \\includegraphics controls the final printed size independently
of how large the source file looks on a screen.

Figure order:
  1. M1  -- CVSS Base-Metric accuracy heatmap
  2. M2  -- CVSS Base Score MAE
  3. supporting -- raw Trivy vs. SAMVA-derived severity (before/after)
  4. supporting -- final SAMVA severity distribution (pie charts)
  5. M3  -- rank-shift dumbbell plot
  6. M4  -- CWE fallback exact-match accuracy, with confidence intervals
  7. M5  -- complete enrichment rate
  8. M6  -- temporal reassessment (directional accuracy over time)

Run this AFTER all 3 scenarios have their real trivy/nvd/epss files in
place. Needs: trivy_scenarioN.json, nvd_data_lookup_scenarioN.json,
epss_lookup_scenarioN.json, epss_historical_scenarioN.json for N=1,2,3,
plus refined_model_frozen.joblib.

Usage:
    python3 generate_comparison_visualizations.py
"""

import json

import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import pandas as pd

from compute_m1_m2_scenario import run_scenario_evaluation
from compute_m4 import run_m4_evaluation
from compute_m5 import compute_m5
from compute_m6 import run_m6_evaluation
from phase1_ingest import load_trivy_findings
from phase2_enrich import run_phase2
from phase3_score import score_finding
from apply_ml_fallback import apply_ml_fallback, add_samva_severity
from cwe_fallback import apply_cwe_fallback
from phase4_adjust import adjust_finding
from config import EPSS_MEANINGFUL_CHANGE_THRESHOLD

# --- Clean academic styling -- no internal gridlines, generous font sizes
# for on-screen clarity. PDF export is vector, so LaTeX can still place
# these at exact IEEE column widths without any loss of sharpness. ---
mpl.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "black",
    "axes.grid": False,
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "savefig.dpi": 300,
})

SCENARIOS = [
    {"name": "Online Boutique", "short_name": "OB", "trivy_file": "trivy_scenario1.json",
     "nvd_file": "nvd_data_lookup_scenario1.json", "epss_file": "epss_lookup_scenario1.json",
     "epss_historical_file": "epss_historical_scenario1.json", "color": "#264653"},
    {"name": "Train-Ticket", "short_name": "TT", "trivy_file": "trivy_scenario2.json",
     "nvd_file": "nvd_data_lookup_scenario2.json", "epss_file": "epss_lookup_scenario2.json",
     "epss_historical_file": "epss_historical_scenario2.json", "color": "#2A9D8F"},
    {"name": "TeaStore", "short_name": "TS", "trivy_file": "trivy_scenario3.json",
     "nvd_file": "nvd_data_lookup_scenario3.json", "epss_file": "epss_lookup_scenario3.json",
     "epss_historical_file": "epss_historical_scenario3.json", "color": "#D79A2B"},
]

THE_8_CVSS_METRIC_NAMES = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "#8B0000", "HIGH": "#D73027", "MEDIUM": "#F57C00",
    "LOW": "#388E3C", "UNKNOWN": "#808080", "NONE": "#808080",
}


def save_figure(fig, base_filename):
    fig.savefig(f"{base_filename}.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{base_filename}.pdf", bbox_inches="tight")
    print(f"Saved {base_filename}.png and {base_filename}.pdf")


def collect_all_results_for_one_scenario(scenario):
    print(f"\n{'='*60}\nCollecting results for {scenario['short_name']} ({scenario['name']})\n{'='*60}")

    nvd_lookup_table = {}
    try:
        with open(scenario["nvd_file"]) as f:
            nvd_lookup_table = json.load(f)
    except FileNotFoundError:
        print(f"  NOTE: {scenario['nvd_file']} not found -- proceeding without NVD gap-fill data.")

    m1_m2_results = run_scenario_evaluation(scenario["trivy_file"], scenario["short_name"], scenario["nvd_file"])
    print("  M1/M2 done.")

    m4_results = run_m4_evaluation(scenario["trivy_file"])
    print("  M4 done.")

    raw_findings = load_trivy_findings(scenario["trivy_file"])
    enriched_findings, _ = run_phase2(raw_findings)

    before_severity_counts = {band: 0 for band in SEVERITY_ORDER}
    for finding in enriched_findings:
        band = finding.get("raw_severity", "UNKNOWN").upper()
        if band not in before_severity_counts:
            band = "UNKNOWN"
        before_severity_counts[band] += 1

    # One shared record set, built once, used consistently for the
    # after-severity tally, M3's real per-CVE ranks, M5, and M6 -- so
    # the "before" and "after" severity tallies are guaranteed to be
    # counted over the exact same deduplicated findings.
    scored_findings = [score_finding(f, nvd_lookup_table=nvd_lookup_table) for f in enriched_findings]
    scored_findings = apply_ml_fallback(scored_findings)
    scored_findings = add_samva_severity(scored_findings)
    scored_findings = apply_cwe_fallback(scored_findings, nvd_lookup_table)
    adjusted_findings = [adjust_finding(f) for f in scored_findings]

    after_severity_counts = {band: 0 for band in SEVERITY_ORDER}
    for finding in adjusted_findings:
        band = finding.get("samva_severity", "UNKNOWN").upper()
        if band not in after_severity_counts:
            band = "UNKNOWN"
        after_severity_counts[band] += 1

    seen_cve_ids = set()
    m3_records = []
    for finding in adjusted_findings:
        has_both = finding.get("adjusted_score") is not None and finding.get("cvss_v3_score") is not None
        if has_both and finding["cve_id"] not in seen_cve_ids:
            m3_records.append({
                "cve_id": finding["cve_id"],
                "cvss_only_score": finding["cvss_v3_score"],
                "samva_score": finding["adjusted_score"],
            })
            seen_cve_ids.add(finding["cve_id"])

    m3_df = pd.DataFrame(m3_records)
    m3_spearman_rho, m3_p_value, m3_sample_size = None, None, 0
    if len(m3_df) >= 2:
        from scipy.stats import spearmanr
        m3_spearman_rho, m3_p_value = spearmanr(m3_df["samva_score"], m3_df["cvss_only_score"])
        m3_sample_size = len(m3_df)
        m3_df["cvss_rank"] = m3_df["cvss_only_score"].rank(ascending=False, method="min").astype(int)
        m3_df["samva_rank"] = m3_df["samva_score"].rank(ascending=False, method="min").astype(int)
        m3_df["rank_change"] = m3_df["cvss_rank"] - m3_df["samva_rank"]
    print("  M3 done.")

    try:
        with open(scenario["epss_file"]) as f:
            epss_lookup = json.load(f)
    except FileNotFoundError:
        epss_lookup = {}
    m5_results = compute_m5(adjusted_findings, epss_lookup)
    print("  M5 done.")

    m6_results = run_m6_evaluation(scenario["trivy_file"], scenario["epss_historical_file"], scenario["nvd_file"])
    print("  M6 done.")

    combined = {
        "scenario": scenario["name"], "short_name": scenario["short_name"], "color": scenario["color"],
        "m1_m2": m1_m2_results, "m4": m4_results, "m5": m5_results, "m6": m6_results,
        "before_severity": before_severity_counts, "after_severity": after_severity_counts,
        "m3_dataframe": m3_df, "m3_spearman_rho": m3_spearman_rho,
        "m3_p_value": m3_p_value, "m3_sample_size": m3_sample_size,
        "total_deduplicated_findings": len(enriched_findings),
    }

    output_file_name = f"combined_results_{scenario['short_name']}.json"
    json_safe = {k: v for k, v in combined.items() if k != "m3_dataframe"}
    with open(output_file_name, "w") as f:
        json.dump(json_safe, f, indent=2, default=str)
    print(f"  Saved to {output_file_name}")

    return combined


def build_figure_1_m1_heatmap(all_scenario_results):
    accuracy_grid = []
    precision_recall_f1_rows = []
    for metric_name in THE_8_CVSS_METRIC_NAMES:
        row = []
        for result in all_scenario_results:
            per_metric = result["m1_m2"].get("primary_per_metric_results", {})
            metric_data = per_metric.get(metric_name, {})
            accuracy = metric_data.get("accuracy_pct")
            row.append(accuracy if accuracy is not None else np.nan)
            precision_recall_f1_rows.append({
                "metric": metric_name, "scenario": result["short_name"],
                "precision_pct": metric_data.get("precision_macro_pct"),
                "recall_pct": metric_data.get("recall_macro_pct"),
                "f1_pct": metric_data.get("macro_f1_pct"),
                "sample_size": metric_data.get("sample_size"),
            })
        accuracy_grid.append(row)

    scenario_labels = [r["short_name"] for r in all_scenario_results]

    fig, ax = plt.subplots(figsize=(7, 8))
    im = ax.imshow(accuracy_grid, cmap="Blues", vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(range(len(scenario_labels)))
    ax.set_xticklabels(scenario_labels, fontsize=12)
    ax.set_yticks(range(len(THE_8_CVSS_METRIC_NAMES)))
    ax.set_yticklabels(THE_8_CVSS_METRIC_NAMES, fontsize=12)

    for row_index in range(len(THE_8_CVSS_METRIC_NAMES)):
        for col_index in range(len(scenario_labels)):
            value = accuracy_grid[row_index][col_index]
            text = f"{value:.1f}" if not np.isnan(value) else "N/A"
            text_color = "white" if (not np.isnan(value) and value > 60) else "black"
            ax.text(col_index, row_index, text, ha="center", va="center", fontsize=12, color=text_color)

    cbar = fig.colorbar(im, ax=ax, label="Accuracy (%)", fraction=0.046, pad=0.04)
    fig.tight_layout()
    save_figure(fig, "fig1_m1_heatmap")
    plt.show()

    prf_df = pd.DataFrame(precision_recall_f1_rows)
    prf_df.to_csv("table_m1_precision_recall_f1.csv", index=False)
    print("Saved table_m1_precision_recall_f1.csv")

    severity_rows = []
    for result in all_scenario_results:
        secondary = result["m1_m2"].get("secondary_derived_severity", {})
        severity_rows.append({
            "scenario": result["short_name"],
            "derived_severity_accuracy_pct": secondary.get("accuracy_pct"),
            "derived_severity_macro_f1_pct": secondary.get("macro_f1_pct"),
            "sample_size": secondary.get("sample_size"),
        })
    severity_df = pd.DataFrame(severity_rows)
    severity_df.to_csv("table_derived_severity_downstream.csv", index=False)
    print("Saved table_derived_severity_downstream.csv (downstream result, not a formal metric)")


def build_figure_2_m2_mae(all_scenario_results):
    scenario_labels = [r["short_name"] for r in all_scenario_results]
    scenario_colors = [r["color"] for r in all_scenario_results]
    maes = [r["m1_m2"].get("secondary_derived_severity", {}).get("mae", 0) for r in all_scenario_results]
    sample_sizes = [r["m1_m2"].get("secondary_derived_severity", {}).get("sample_size", 0) for r in all_scenario_results]

    fig, ax = plt.subplots(figsize=(7, 5.5))
    bars = ax.bar(scenario_labels, maes, color=scenario_colors, width=0.55)

    for bar, mae, n in zip(bars, maes, sample_sizes):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                f"{mae:.3f}\n(n={n})", ha="center", fontsize=11)

    ax.set_ylabel("CVSS Base Score MAE")
    ax.set_ylim(0, max(maes) * 1.35 if maes else 1)
    fig.tight_layout()
    save_figure(fig, "fig2_m2_mae")
    plt.show()
    print("  Caption note: n = number of eligible vulnerability records with both an actual "
          "(NVD/Trivy-authoritative) and a predicted CVSS Base Score. Each unique CVE is counted "
          "once per scenario, not once per affected asset/service and not once per CVSS sub-metric.")

    pd.DataFrame({"scenario": scenario_labels, "mae": maes, "sample_size": sample_sizes}).to_csv(
        "table_m2_mae.csv", index=False)
    print("Saved table_m2_mae.csv")


def build_figure_3_before_after(all_scenario_results):
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    csv_rows = []
    for ax, result in zip(axes, all_scenario_results):
        before_total = sum(result["before_severity"].values()) or 1
        after_total = sum(result["after_severity"].values()) or 1
        before_pcts = [100 * result["before_severity"].get(b, 0) / before_total for b in SEVERITY_ORDER]
        after_pcts = [100 * result["after_severity"].get(b, 0) / after_total for b in SEVERITY_ORDER]

        x_positions = np.arange(len(SEVERITY_ORDER))
        bar_width = 0.35
        ax.bar(x_positions - bar_width/2, before_pcts, bar_width, color="#808080", label="Raw Trivy")
        ax.bar(x_positions + bar_width/2, after_pcts, bar_width, color=result["color"], label="SAMVA-derived")

        for x, pct in zip(x_positions - bar_width/2, before_pcts):
            if pct > 0:
                ax.text(x, pct + 1.5, f"{pct:.0f}", ha="center", fontsize=10)
        for x, pct in zip(x_positions + bar_width/2, after_pcts):
            if pct > 0:
                ax.text(x, pct + 1.5, f"{pct:.0f}", ha="center", fontsize=10)

        ax.set_xticks(x_positions)
        ax.set_xticklabels([b.capitalize() for b in SEVERITY_ORDER], rotation=30, ha="right", fontsize=10)
        ax.set_title(f"{result['short_name']} (n={before_total})", fontsize=12)
        ax.set_ylim(0, 100)
        if ax is axes[0]:
            ax.set_ylabel("Percent of Findings")
        ax.legend(fontsize=9, loc="upper right")

        for band, before_pct, after_pct, before_n, after_n in zip(
                SEVERITY_ORDER, before_pcts, after_pcts,
                [result["before_severity"].get(b, 0) for b in SEVERITY_ORDER],
                [result["after_severity"].get(b, 0) for b in SEVERITY_ORDER]):
            csv_rows.append({"scenario": result["short_name"], "severity_band": band,
                              "raw_trivy_count": before_n, "raw_trivy_pct": round(before_pct, 2),
                              "samva_derived_count": after_n, "samva_derived_pct": round(after_pct, 2)})

    fig.tight_layout()
    save_figure(fig, "fig3_before_after_severity")
    plt.show()
    print("  Caption note: percentages are rounded to the nearest whole number; scenario denominator (n) "
          "is shown in each panel title. Before and After values are computed over the exact same "
          "asset-level deduplicated findings for that scenario -- only the severity label attached to "
          "each finding differs, not the underlying set of findings.")

    pd.DataFrame(csv_rows).to_csv("table_before_after_severity.csv", index=False)
    print("Saved table_before_after_severity.csv")


def build_figure_4_severity_pies(all_scenario_results):
    fig, axes = plt.subplots(1, 3, figsize=(16, 6))

    for ax, result in zip(axes, all_scenario_results):
        counts = result["after_severity"]
        total = sum(counts.values()) or 1
        labels = [band for band in SEVERITY_ORDER if counts.get(band, 0) > 0]
        values = [counts[band] for band in labels]
        colors = [SEVERITY_COLORS[band] for band in labels]

        ax.pie(values, labels=[l.capitalize() for l in labels], colors=colors, autopct="%1.1f%%",
               startangle=90, textprops={"fontsize": 10})
        ax.set_title(f"{result['short_name']} (n={total})", fontsize=12)

    fig.suptitle("Final SAMVA-Derived Severity Distribution by Scenario", fontsize=13, y=1.03)
    fig.tight_layout()
    save_figure(fig, "fig4_severity_pies")
    plt.show()


def build_figure_5_m3_dumbbell(all_scenario_results):
    fig, axes = plt.subplots(1, 3, figsize=(18, 8))

    all_rank_change_rows = []

    for ax, result in zip(axes, all_scenario_results):
        m3_df = result["m3_dataframe"]
        rho = result["m3_spearman_rho"]
        n = result["m3_sample_size"]

        if m3_df is None or len(m3_df) == 0 or rho is None:
            ax.text(0.5, 0.5, "N/A", ha="center", va="center", fontsize=11)
            ax.set_title(result["short_name"])
            continue

        for _, row in m3_df.iterrows():
            all_rank_change_rows.append({
                "scenario": result["short_name"], "cve_id": row["cve_id"],
                "cvss_only_rank": int(row["cvss_rank"]), "samva_rank": int(row["samva_rank"]),
                "rank_change": int(row["rank_change"]),
            })

        top_10 = m3_df.reindex(m3_df["rank_change"].abs().sort_values(ascending=False).index).head(10)
        top_10 = top_10.sort_values("cvss_rank")

        y_positions = np.arange(len(top_10))
        for y, (_, row) in zip(y_positions, top_10.iterrows()):
            color = result["color"] if row["rank_change"] > 0 else "#808080"
            ax.plot([row["cvss_rank"], row["samva_rank"]], [y, y], color=color, linewidth=2, zorder=1)
            ax.scatter(row["cvss_rank"], y, color="#808080", s=60, zorder=2, marker="o")
            ax.scatter(row["samva_rank"], y, color=result["color"], s=60, zorder=2, marker="o")

        ax.set_yticks(y_positions)
        ax.set_yticklabels(top_10["cve_id"], fontsize=9)
        ax.set_xlabel("Rank (1 = highest priority)")
        ax.set_title(f"{result['short_name']}: \u03c1={rho:.3f}, n={n}", fontsize=12)
        ax.invert_yaxis()

    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#808080', markersize=9, label='CVSS-only rank'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='#264653', markersize=9, label='SAMVA rank'),
    ]
    fig.legend(handles=legend_elements, loc="lower center", ncol=2, fontsize=10, bbox_to_anchor=(0.5, -0.03))
    fig.tight_layout()
    save_figure(fig, "fig5_m3_rank_shift_dumbbell")
    plt.show()
    print("  Caption note: \u03c1 is Spearman's rank correlation (not a p-value), computed over the full "
          "population (n); the 10 CVEs with the largest |rank change| are plotted. Rank 1 = highest "
          "priority, so a point moving LEFT (toward rank 1) is a promotion by SAMVA relative to "
          "CVSS-only ranking, and a point moving RIGHT is a demotion.")

    pd.DataFrame(all_rank_change_rows).to_csv("table_m3_rank_changes.csv", index=False)
    print("Saved table_m3_rank_changes.csv (full population, not just the top 10 shown)")


def _wilson_score_interval(correct_count, total_count, z=1.96):
    if total_count == 0:
        return 0.0, 0.0, 0.0
    p_hat = correct_count / total_count
    denominator = 1 + (z**2) / total_count
    center = (p_hat + (z**2) / (2 * total_count)) / denominator
    margin = (z / denominator) * np.sqrt((p_hat * (1 - p_hat) / total_count) + (z**2) / (4 * total_count**2))
    return p_hat, max(0.0, center - margin), min(1.0, center + margin)


def build_figure_6_m4_confidence(all_scenario_results):
    fig, ax = plt.subplots(figsize=(7, 5.5))

    csv_rows = []
    for index, result in enumerate(all_scenario_results):
        m4 = result["m4"]
        if "error" in m4:
            ax.text(index, 5, "N/A", ha="center", fontsize=10, color="red")
            continue
        test_size = m4.get("test_set_size", 0)
        accuracy_pct = m4.get("M4_cwe_mapping_accuracy_pct", 0)
        correct_count = round(accuracy_pct / 100 * test_size) if test_size else 0

        p_hat, lower, upper = _wilson_score_interval(correct_count, test_size)
        lower_error = (p_hat - lower) * 100
        upper_error = (upper - p_hat) * 100
        ax.errorbar(index, p_hat * 100, yerr=[[lower_error], [upper_error]],
                     fmt="o", color=result["color"], markersize=11, capsize=7, elinewidth=2)
        ax.text(index, upper * 100 + 5, f"{correct_count}/{test_size}", ha="center", fontsize=11)
        csv_rows.append({"scenario": result["short_name"], "correct": correct_count, "total": test_size,
                          "accuracy_pct": round(p_hat * 100, 1), "ci_lower_pct": round(lower * 100, 1),
                          "ci_upper_pct": round(upper * 100, 1)})

    ax.set_xticks(range(len(all_scenario_results)))
    ax.set_xticklabels([r["short_name"] for r in all_scenario_results], fontsize=12)
    ax.set_ylabel("CWE Mapping Accuracy (%)")
    ax.set_ylim(0, 110)
    fig.tight_layout()
    save_figure(fig, "fig6_m4_cwe_confidence")
    plt.show()

    pd.DataFrame(csv_rows).to_csv("table_m4_wilson_results.csv", index=False)
    print("Saved table_m4_wilson_results.csv")


def build_figure_7_m5_completeness(all_scenario_results):
    scenario_labels = [r["short_name"] for r in all_scenario_results]
    scenario_colors = [r["color"] for r in all_scenario_results]

    numerators, denominators, percentages = [], [], []
    field_rows = []
    for result in all_scenario_results:
        m5 = result["m5"]
        numerator = m5.get("fully_enriched_count", 0)
        denominator = m5.get("total_deduplicated_findings", 0) or 1
        numerators.append(numerator)
        denominators.append(denominator)
        percentages.append(100 * numerator / denominator)

        breakdown = m5.get("field_level_breakdown", {})
        field_rows.append({
            "scenario": result["short_name"],
            "cve_coverage_pct": round(100 * breakdown.get("has_cve", 0) / denominator, 2),
            "cvss_coverage_pct": round(100 * breakdown.get("has_cvss", 0) / denominator, 2),
            "cwe_coverage_pct": round(100 * breakdown.get("has_cwe", 0) / denominator, 2),
            "complete_numerator": numerator, "complete_denominator": denominator,
            "complete_pct": round(100 * numerator / denominator, 2),
        })

    fig, ax = plt.subplots(figsize=(7, 5.5))
    bars = ax.bar(scenario_labels, percentages, color=scenario_colors, width=0.55)
    for bar, num, denom, pct in zip(bars, numerators, denominators, percentages):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 3,
                f"{num}/{denom}\n({pct:.1f}%)", ha="center", fontsize=11)

    ax.set_xticks(range(len(scenario_labels)))
    ax.set_xticklabels(scenario_labels, fontsize=12)
    ax.set_ylabel("Complete Enrichment Rate (%)")
    ax.set_ylim(0, 118)
    fig.tight_layout()
    save_figure(fig, "fig7_m5_completeness")
    plt.show()

    pd.DataFrame(field_rows).to_csv("table_m5_completeness.csv", index=False)
    print("Saved table_m5_completeness.csv (includes individual CVE/CVSS/CWE coverage)")


def build_figure_8_m6_temporal(all_scenario_results):
    print(f"\n  M6 threshold (defined before analysis, applied identically to every scenario): "
          f"a CVE's EPSS score must change by at least {EPSS_MEANINGFUL_CHANGE_THRESHOLD} between the "
          f"two comparison dates to count as a meaningful, evaluable movement.")

    plottable_results = [r for r in all_scenario_results if r["m6"].get("sample_results")]

    fig, axes = plt.subplots(1, len(plottable_results), figsize=(16, 7))
    if len(plottable_results) == 1:
        axes = [axes]

    all_m6_rows = []

    for ax, result in zip(axes, plottable_results):
        m6 = result["m6"]
        all_results = m6.get("sample_results", [])
        date_early = m6.get("date_early", "Early")
        date_late = m6.get("date_late", "Late")
        cves_evaluated = m6.get("cves_evaluated", 0)
        accuracy_pct = m6.get("M6_directional_update_accuracy_pct", 0)
        correct_count = round(accuracy_pct / 100 * cves_evaluated) if cves_evaluated else 0

        for r in all_results:
            all_m6_rows.append({"scenario": result["short_name"], **r})

        incorrect_results = [r for r in all_results if not r.get("correct")]
        MAX_TOTAL_SHOWN = 15
        selection_note = ""
        if len(all_results) > MAX_TOTAL_SHOWN:
            top_by_change = sorted(all_results, key=lambda r: abs(r.get("epss_change", 0)), reverse=True)[:10]
            shown_ids = set(r["cve_id"] for r in top_by_change) | set(r["cve_id"] for r in incorrect_results)
            shown_results = [r for r in all_results if r["cve_id"] in shown_ids]
            selection_note = f" (showing {len(shown_results)} of {cves_evaluated} eligible CVEs: the 10 largest EPSS changes plus all incorrect cases)"
        else:
            shown_results = all_results

        # Draw correct (green) cases first, incorrect (red) cases last --
        # this guarantees an incorrect case is never visually hidden
        # underneath a correct one with a similar trajectory, since
        # whichever line is drawn last renders on top.
        correct_cases = [r for r in shown_results if r.get("correct")]
        incorrect_cases = [r for r in shown_results if not r.get("correct")]

        for cve_result in correct_cases + incorrect_cases:
            early = cve_result.get("epss_early", 0)
            late = cve_result.get("epss_late", 0)
            color = "#388E3C" if cve_result.get("correct") else "#D73027"
            line_width = 1.6 if cve_result.get("correct") else 2.4
            z_order = 1 if cve_result.get("correct") else 3
            ax.plot([0, 1], [early, late], color=color, marker="o", markersize=6,
                    linewidth=line_width, alpha=0.9, zorder=z_order)

        ax.set_xticks([0, 1])
        ax.set_xticklabels([date_early, date_late], fontsize=11)
        ax.set_ylabel("EPSS Probability")
        ax.set_title(f"{result['short_name']}: {correct_count}/{cves_evaluated} = {accuracy_pct:.1f}%"
                     f"{selection_note}\n(directional accuracy calculated using all {cves_evaluated} eligible CVEs)",
                     fontsize=10)

    fig.suptitle("Green = SAMVA Adjusted Score direction matches EPSS direction; Red = does not", fontsize=11, y=1.06)
    fig.tight_layout()
    save_figure(fig, "fig8_m6_temporal_reassessment")
    plt.show()

    pd.DataFrame(all_m6_rows).to_csv("table_m6_per_cve_evidence.csv", index=False)
    print("Saved table_m6_per_cve_evidence.csv (complete per-CVE data, all scenarios)")

    ob_result = next((r for r in all_scenario_results if r["short_name"] == "OB"), None)
    if ob_result:
        ob_m6 = ob_result["m6"]
        eligible = ob_m6.get('cves_with_epss_at_both_dates', 0)
        if eligible == 1:
            print(f"\nOnline Boutique (not plotted): One CVE had EPSS observations at both dates, but its "
                  f"change did not exceed the pre-specified {EPSS_MEANINGFUL_CHANGE_THRESHOLD} threshold; "
                  f"therefore, directional accuracy was not calculated.")
        else:
            print(f"\nOnline Boutique (not plotted): {eligible} CVE(s) had EPSS observations at both dates; "
                  f"none exceeded the pre-specified {EPSS_MEANINGFUL_CHANGE_THRESHOLD} threshold; "
                  f"therefore, directional accuracy was not calculated.")


def export_scenario_preparation_table(all_scenario_results):
    rows = []
    for result in all_scenario_results:
        rows.append({
            "scenario": result["short_name"], "name": result["scenario"],
            "total_deduplicated_findings": result["total_deduplicated_findings"],
            "m1_m2_ground_truth_used": result["m1_m2"].get("dataset_info", {}).get("ground_truth_records_used"),
            "excluded_training_overlap": result["m1_m2"].get("dataset_info", {}).get("excluded_due_to_training_overlap"),
        })
    pd.DataFrame(rows).to_csv("table_scenario_preparation.csv", index=False)
    print("Saved table_scenario_preparation.csv")


def export_m1_classification_table(all_scenario_results):
    rows = []
    for result in all_scenario_results:
        for metric_name, metric_data in result["m1_m2"].get("primary_per_metric_results", {}).items():
            rows.append({"scenario": result["short_name"], "metric": metric_name, **metric_data})
    pd.DataFrame(rows).to_csv("table_m1_classification_results.csv", index=False)
    print("Saved table_m1_classification_results.csv")


def main():
    all_scenario_results = []
    for scenario in SCENARIOS:
        try:
            result = collect_all_results_for_one_scenario(scenario)
            all_scenario_results.append(result)
        except FileNotFoundError as error:
            print(f"  SKIPPING {scenario['short_name']} -- missing file: {error}")

    if len(all_scenario_results) < 2:
        print("\nNeed at least 2 scenarios with complete data to build comparison figures.")
        return

    print(f"\n{'='*60}\nBuilding all 8 report figures for {len(all_scenario_results)} scenario(s)\n{'='*60}")

    export_scenario_preparation_table(all_scenario_results)
    build_figure_1_m1_heatmap(all_scenario_results)
    export_m1_classification_table(all_scenario_results)
    build_figure_2_m2_mae(all_scenario_results)
    build_figure_3_before_after(all_scenario_results)
    build_figure_4_severity_pies(all_scenario_results)
    build_figure_5_m3_dumbbell(all_scenario_results)
    build_figure_6_m4_confidence(all_scenario_results)
    build_figure_7_m5_completeness(all_scenario_results)
    build_figure_8_m6_temporal(all_scenario_results)

    print("\nAll done. 8 figures (PNG+PDF) + 9 supporting CSV tables saved, ready for the IEEE report.")


if __name__ == "__main__":
    main()
