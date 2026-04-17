"""
ML pipeline construction.

Architecture: TF-IDF + Logistic Regression
Rationale:
  - Fast inference (<1ms per sample)
  - No GPU required
  - Interpretable — we can inspect feature weights
  - Well-suited for text classification with moderate data
  - Production-proven for security classification tasks

With 500-5000 samples per class, TF-IDF + LR outperforms
shallow neural nets and matches fine-tuned transformers on
short adversarial text.
"""

from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder


def build_pipeline(
    ngram_range:  tuple[int, int] = (1, 3),
    max_features: int             = 50_000,
    C:            float           = 1.0,
    max_iter:     int             = 2000,
) -> Pipeline:
    """
    Build the TF-IDF + Logistic Regression pipeline.

    ngram_range:  (1,3) captures unigrams, bigrams, trigrams
                  Critical for detecting multi-word attack patterns:
                  "ignore all previous" is a trigram trigger

    max_features: 50k features (up from 10k in v1)
                  More features = better generalisation with larger dataset

    C:            Regularisation strength (lower = more regularised)
                  1.0 is a good starting point, tuned in tune.py

    class_weight: "balanced" — critical for imbalanced classes
                  Weights each class inversely proportional to frequency
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range   = ngram_range,
            max_features  = max_features,
            sublinear_tf  = True,       # log(1+tf) — reduces impact of high-freq terms
            strip_accents  = "unicode",
            analyzer      = "word",
            token_pattern = r"(?u)\b\w+\b",
            min_df        = 2,          # ignore terms that appear < 2 times
            max_df        = 0.95,       # ignore terms that appear in >95% of docs
        )),
        ("clf", LogisticRegression(
            max_iter     = max_iter,
            C            = C,
            class_weight = "balanced",
            solver       = "lbfgs",
            multi_class  = "multinomial",
            n_jobs       = -1,          # use all CPU cores
        )),
    ])
