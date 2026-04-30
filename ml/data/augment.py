# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Data augmentation for underrepresented classes.

Techniques used:
  1. Case variation         — uppercase/lowercase variants
  2. Punctuation removal    — removes dots, commas etc.
  3. Number substitution    — replaces real numbers with placeholders
  4. Synonym replacement    — simple word-level synonyms for key terms
  5. Paraphrase templates   — reordering and rephrasing

Only applied to classes with fewer than MIN_SAMPLES samples.
Never applied to classes loaded from HuggingFace (already large enough).
"""

from __future__ import annotations

import logging
import random
import re

import pandas as pd

logger = logging.getLogger("wrapsec.ml.augment")

MIN_SAMPLES   = 400   # augment classes below this threshold
TARGET_SAMPLES = 800  # augment up to this many samples per class

# Simple synonym map for key security terms
SYNONYMS = {
    "send":      ["transmit", "forward", "upload", "export", "transfer"],
    "get":       ["retrieve", "fetch", "extract", "obtain", "access"],
    "show":      ["display", "reveal", "expose", "list", "print"],
    "all":       ["every", "entire", "complete", "full", "whole"],
    "data":      ["information", "records", "files", "content", "details"],
    "user":      ["account", "customer", "person", "member", "client"],
    "password":  ["credential", "passphrase", "secret", "key", "token"],
    "database":  ["db", "datastore", "storage", "repository", "system"],
    "hack":      ["break into", "compromise", "infiltrate", "attack", "exploit"],
    "steal":     ["take", "exfiltrate", "copy", "grab", "harvest"],
    "ignore":    ["disregard", "forget", "bypass", "skip", "override"],
    "previous":  ["prior", "earlier", "old", "former", "initial"],
    "instructions": ["guidelines", "rules", "directives", "commands", "prompts"],
}


def _replace_synonyms(text: str, n_replacements: int = 2) -> str:
    """Replace up to n random words with synonyms."""
    words = text.split()
    replaced = 0
    for i, word in enumerate(words):
        lower = word.lower().rstrip(".,!?;:")
        if lower in SYNONYMS and replaced < n_replacements:
            synonym = random.choice(SYNONYMS[lower])
            words[i] = synonym
            replaced += 1
    return " ".join(words)


def _remove_punctuation(text: str) -> str:
    """Remove most punctuation — tests robustness to formatting."""
    return re.sub(r"[.,;:!?]", "", text)


def _number_substitution(text: str) -> str:
    """Replace specific numbers with generic placeholders."""
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "XXX-XX-XXXX", text)   # SSN
    text = re.sub(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b", "XXXX XXXX XXXX XXXX", text)  # CC
    text = re.sub(r"\b\d{10,}\b", "XXXXXXXXXX", text)  # long numbers
    return text


def _case_variant(text: str) -> str:
    """Random case variation — UPPERCASE or Title Case."""
    choice = random.random()
    if choice < 0.33:
        return text.upper()
    elif choice < 0.66:
        return text.title()
    return text.lower()


def augment_sample(text: str) -> list[str]:
    """
    Generate augmented variants of a single sample.
    Returns a list of new samples (not including the original).
    """
    variants = []

    # Variant 1: synonym replacement
    v1 = _replace_synonyms(text, n_replacements=1)
    if v1 != text:
        variants.append(v1)

    # Variant 2: synonym replacement (more aggressive)
    v2 = _replace_synonyms(text, n_replacements=3)
    if v2 != text and v2 not in variants:
        variants.append(v2)

    # Variant 3: punctuation removal
    v3 = _remove_punctuation(text)
    if v3 != text and len(v3) > 5:
        variants.append(v3)

    # Variant 4: number substitution
    v4 = _number_substitution(text)
    if v4 != text:
        variants.append(v4)

    # Variant 5: case variant
    v5 = _case_variant(text)
    if v5 != text.lower():
        variants.append(v5)

    return variants


def augment_dataframe(
    df: pd.DataFrame,
    min_samples:    int = MIN_SAMPLES,
    target_samples: int = TARGET_SAMPLES,
    seed:           int = 42,
) -> pd.DataFrame:
    """
    Augment classes that have fewer than min_samples samples.
    Augmented samples are marked with source='augmented'.

    Only augments curated classes — never HuggingFace sourced classes.
    """
    random.seed(seed)
    augmented_rows = []

    for label_id in df["label"].unique():
        class_df   = df[df["label"] == label_id]
        class_count = len(class_df)

        if class_count >= min_samples:
            continue

        # Only augment curated sources
        curated = class_df[class_df["source"] == "curated"]
        if len(curated) == 0:
            continue

        needed   = target_samples - class_count
        logger.info(
            f"Augmenting label {label_id}: "
            f"{class_count} → target {target_samples} ({needed} new samples needed)"
        )

        generated = 0
        attempts  = 0
        max_attempts = needed * 10

        curated_texts = curated["text"].tolist()

        while generated < needed and attempts < max_attempts:
            source_text = random.choice(curated_texts)
            variants    = augment_sample(source_text)
            for v in variants:
                if generated >= needed:
                    break
                existing = set(df["text"].tolist()) | {r["text"] for r in augmented_rows}
                if v not in existing:
                    augmented_rows.append({
                        "text":   v,
                        "label":  label_id,
                        "source": "augmented",
                    })
                    generated += 1
            attempts += 1

        logger.info(f"  Generated {generated} augmented samples for label {label_id}")

    if augmented_rows:
        augmented_df = pd.DataFrame(augmented_rows)
        df = pd.concat([df, augmented_df], ignore_index=True)
        df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return df
