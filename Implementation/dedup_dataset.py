"""
Near-duplicate removal for the SAMVA training dataset.

Exact-duplicate CVE IDs are already impossible here (one row per CVE by
construction), but NEAR-duplicate DESCRIPTIONS are a real, separate risk:
- Template-generated advisories for the same product line across many CVEs
  (e.g. "SQL injection in <Product> before version X" repeated with only the
  version number changed)
- A CVE that was later split/renumbered, producing two IDs with near-identical
  text

If two near-duplicate descriptions land on opposite sides of the train/test
split, the model can effectively "memorise" the answer rather than generalise
-- the same class of leakage this project already caught once before at
mid-term (the CVE-per-microservice duplication bug in M1/M2/M4).
"""

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

SIMILARITY_THRESHOLD = 0.95  # descriptions this similar are treated as near-duplicates


def find_near_duplicate_groups(descriptions: pd.Series, threshold: float = SIMILARITY_THRESHOLD):
    """
    Returns a list of groups (each group = a list of row-index positions) where
    every description in a group is >= threshold cosine-similar to at least
    one other member of that group. Singletons (no near-duplicate found) are
    not included in the output.

    Uses word-level TF-IDF + cosine similarity in batches, since a full
    N x N similarity matrix over ~90k descriptions would need far too much
    memory computed all at once.
    """
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    tfidf_matrix = vectorizer.fit_transform(descriptions.fillna(""))

    n_records = tfidf_matrix.shape[0]
    batch_size = 2000
    parent = list(range(n_records))  # union-find for grouping near-duplicates transitively

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[ri] = rj

    for start in range(0, n_records, batch_size):
        end = min(start + batch_size, n_records)
        # Compare this batch against itself AND every batch after it, so no
        # pair is missed, without ever building the full N x N matrix at once.
        for compare_start in range(start, n_records, batch_size):
            compare_end = min(compare_start + batch_size, n_records)
            sims = cosine_similarity(tfidf_matrix[start:end], tfidf_matrix[compare_start:compare_end])
            rows, cols = np.where(sims >= threshold)
            for r, c in zip(rows, cols):
                global_r, global_c = start + r, compare_start + c
                if global_r != global_c:
                    union(global_r, global_c)

    groups: dict[int, list[int]] = {}
    for i in range(n_records):
        root = find(i)
        groups.setdefault(root, []).append(i)

    return [members for members in groups.values() if len(members) > 1]


def remove_near_duplicates(df: pd.DataFrame, description_column: str = "description") -> pd.DataFrame:
    """
    Keeps exactly one record per near-duplicate group (the one with the most
    complete/most recently modified record, as a reasonable tiebreaker), and
    every record that had no near-duplicate at all.
    """
    duplicate_groups = find_near_duplicate_groups(df[description_column])

    rows_to_drop = set()
    for group in duplicate_groups:
        group_df = df.iloc[group]
        # Keep the most recently modified record in each duplicate group --
        # arbitrary but consistent and defensible as a tiebreaker.
        keep_index = group_df["last_modified_date"].idxmax()
        for idx in group_df.index:
            if idx != keep_index:
                rows_to_drop.add(idx)

    print(f"Found {len(duplicate_groups)} near-duplicate group(s), "
          f"totalling {sum(len(g) for g in duplicate_groups)} records.")
    print(f"Dropping {len(rows_to_drop)} records, keeping one representative per group.")

    return df.drop(index=rows_to_drop).reset_index(drop=True)


if __name__ == "__main__":
    df = pd.read_csv("nvd_dataset_scoped.csv")
    print(f"Before near-duplicate removal: {len(df)} records")

    df_deduped = remove_near_duplicates(df)
    print(f"After near-duplicate removal: {len(df_deduped)} records")

    df_deduped.to_csv("nvd_dataset_final.csv", index=False)
    print("Saved to nvd_dataset_final.csv")
