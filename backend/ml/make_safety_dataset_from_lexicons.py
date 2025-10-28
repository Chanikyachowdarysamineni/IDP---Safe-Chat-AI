"""
Create a synthetic safety dataset CSV from provided lexicon files.

Usage:
  python make_safety_dataset_from_lexicons.py --lexicons en.txt hi.txt --out safety_lexicons.csv --neg-mult 3

The script will produce a CSV with columns: text,label
- label=1 -> abusive (contains lexicon word)
- label=0 -> non-abusive (neutral sentences)

This dataset is synthetic and intended as a bootstrap to train the safety classifier or
to augment an existing labeled dataset. For production-grade models, prefer using
carefully labeled human datasets or augment with context-rich examples.
"""
import argparse
import csv
import os
import random
from typing import List

TEMPLATES = [
    "You're a {w}.",
    "What a {w}.",
    "Stop being such a {w}.",
    "I can't believe you {w}.",
    "You are literally {w}.",
    "That's so {w}.",
]

NEUTRAL_SENTENCES = [
    "I had a great day at work.",
    "Let's meet tomorrow to discuss the plan.",
    "The weather is pleasant today.",
    "I enjoyed the movie last night.",
    "Can you send the report by EOD?",
    "I'll be on vacation next week.",
    "Thanks for your help earlier.",
    "This is an example of a neutral sentence.",
]


def load_lexicon_files(paths: List[str]) -> List[str]:
    words = []
    for p in paths:
        if not os.path.isfile(p):
            print(f"Warning: lexicon file not found: {p}")
            continue
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip()
                if not w:
                    continue
                # skip comments
                if w.startswith("#"):
                    continue
                # keep single words only for synthetic generation
                if " " in w:
                    w = w.split()[0]
                words.append(w)
    # dedupe and shuffle
    words = list(dict.fromkeys(words))
    random.shuffle(words)
    return words


def generate_dataset(lexicon_words: List[str], out_csv: str, neg_mult: int = 3, seed: int = 42):
    random.seed(seed)
    rows = []

    # Positive examples (label=1)
    for w in lexicon_words:
        # generate a few variations per lexicon word
        nvar = max(1, min(3, len(w) // 4 + 1))
        for _ in range(nvar):
            tmpl = random.choice(TEMPLATES)
            text = tmpl.format(w=w)
            rows.append((text, 1))

    # Negative examples (label=0) — sample from neutral sentences with small variations
    n_neg = max(100, len(rows) * neg_mult)
    for _ in range(n_neg):
        base = random.choice(NEUTRAL_SENTENCES)
        # optionally append a harmless phrase
        if random.random() < 0.3:
            base = base + " " + random.choice(["Thanks.", "Okay.", "Sure."])
        rows.append((base, 0))

    # Shuffle and write CSV
    random.shuffle(rows)
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    with open(out_csv, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["text", "label"])
        for text, label in rows:
            writer.writerow([text, label])

    print(f"Wrote {len(rows)} rows to {out_csv} (positives: {len(lexicon_words)}, negatives: {n_neg})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lexicons", nargs="+", required=True, help="Paths to lexicon txt files")
    parser.add_argument("--out", default="safety_lexicons.csv", help="Output CSV path")
    parser.add_argument("--neg-mult", type=int, default=3, help="Negative examples multiplier (neg = pos * neg_mult)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    words = load_lexicon_files(args.lexicons)
    if not words:
        print("No lexicon words found. Exiting.")
        return

    generate_dataset(words, args.out, neg_mult=args.neg_mult, seed=args.seed)


if __name__ == "__main__":
    main()
