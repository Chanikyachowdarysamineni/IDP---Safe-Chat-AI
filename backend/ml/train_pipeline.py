"""
Multi-task training pipeline for emotion and safety/behavior detection.

This script orchestrates dataset loading, preprocessing, training, and evaluation
for two models:
  1) Emotion classifier (multi-label) trained on GoEmotions or a custom dataset
  2) Safety/behavior classifier (multi-class or binary) trained on ToxicChat or a
     custom labeled dataset.

Features:
- Download and preprocess HF datasets (if available).
- Accept local CSV/JSONL files (with `text` and `labels` columns) for custom data.
- Train using Hugging Face Transformers `Trainer`.
- Save models, tokenizer, and evaluation reports.

Usage (example):
  python train_pipeline.py \
    --emotion-model roberta-base \
    --safety-model roberta-base \
    --output-dir ./models \
    --epochs 3 \
    --batch-size 16

Notes:
- This script is designed for local runs with a GPU. For CPU-only runs reduce batch size
  and number of epochs.
- It prioritizes reproducibility and explainability (stores label maps and eval reports).
"""
import argparse
import os
import json
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Tuple

import numpy as np

from datasets import load_dataset, Dataset, concatenate_datasets
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
import evaluate


def load_lexicons(paths: Optional[List[str]]) -> List[str]:
    """Load lexicon words from a list of text file paths. Returns a deduped list of words."""
    words: List[str] = []
    if not paths:
        return words
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip()
                    if not w:
                        continue
                    if w.startswith("#"):
                        continue
                    if " " in w:
                        w = w.split()[0]
                    words.append(w)
        except Exception:
            print(f"Warning: could not read lexicon file: {p}")
    # dedupe while preserving order
    seen = set()
    out = []
    for w in words:
        if w in seen:
            continue
        seen.add(w)
        out.append(w)
    return out


@dataclass
class TrainConfig:
    emotion_model_name: str = "roberta-base"
    safety_model_name: str = "roberta-base"
    output_dir: str = "./ml-models"
    epochs: int = 3
    batch_size: int = 16
    lr: float = 2e-5
    seed: int = 42


def load_goemotions(limit: Optional[int] = None) -> Dataset:
    # go_emotions is a multi-label dataset with 'text' and 'labels' fields
    ds = load_dataset("go_emotions", "raw")
    train = ds["train"].map(lambda x: {"text": x["text"], "labels": x["labels"]})
    val = ds["validation"].map(lambda x: {"text": x["text"], "labels": x["labels"]})
    if limit:
        train = train.select(range(min(limit, len(train))))
        val = val.select(range(min(int(limit * 0.1), len(val))))
    return Dataset.from_dict({
        "train_texts": train["text"],
        "train_labels": train["labels"],
        "validation_texts": val["text"],
        "validation_labels": val["labels"],
    })


def prepare_multilabel_dataset(tokenizer, texts: List[str], labels: List[List[int]], max_length=256):
    enc = tokenizer(texts, truncation=True, padding=False, max_length=max_length)
    enc["labels"] = labels
    return enc


def compute_metrics_multilabel(pred):
    metric = evaluate.load("f1")
    logits, labels = pred
    probs = 1 / (1 + np.exp(-logits))
    preds = (probs > 0.5).astype(int)
    # compute micro and macro F1
    results = {}
    results["f1_micro"] = evaluate.load("f1").compute(predictions=preds, references=labels, average="micro")
    results["f1_macro"] = evaluate.load("f1").compute(predictions=preds, references=labels, average="macro")
    return results


def train_emotion_model(config: TrainConfig, output_dir: str, limit: Optional[int] = None):
    print("Loading GoEmotions dataset...")
    # For robustness, allow fallback to a small synthetic set if dataset not available
    try:
        ds = load_dataset("go_emotions")
    except Exception as e:
        raise RuntimeError("Failed to load go_emotions dataset: " + str(e))

    # build label map
    label_list = ds["train"].features["labels"].feature.names
    num_labels = len(label_list)
    print(f"Emotion labels ({num_labels}): {label_list}")

    tokenizer = AutoTokenizer.from_pretrained(config.emotion_model_name)

    def preprocess(batch):
        enc = tokenizer(batch["text"], truncation=True, padding=False)
        enc["labels"] = batch["labels"]
        return enc

    train_ds = ds["train"].map(preprocess, batched=True)
    val_ds = ds["validation"].map(preprocess, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        config.emotion_model_name, num_labels=num_labels, problem_type="multi_label_classification"
    )

    training_args = TrainingArguments(
        output_dir=os.path.join(output_dir, "emotion"),
        evaluation_strategy="epoch",
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        num_train_epochs=config.epochs,
        learning_rate=config.lr,
        seed=config.seed,
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1_macro",
        logging_strategy="steps",
        logging_steps=100,
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    def compute_metrics(eval_pred):
        import numpy as np
        logits, labels = eval_pred
        probs = 1 / (1 + np.exp(-logits))
        preds = (probs > 0.5).astype(int)
        f1 = evaluate.load("f1")
        return {
            "f1_micro": f1.compute(predictions=preds, references=labels, average="micro"),
            "f1_macro": f1.compute(predictions=preds, references=labels, average="macro"),
        }

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    trainer.save_model(os.path.join(output_dir, "emotion"))

    # Save label map and tokenizer info
    os.makedirs(os.path.join(output_dir, "emotion"), exist_ok=True)
    with open(os.path.join(output_dir, "emotion", "label_map.json"), "w", encoding="utf-8") as f:
        json.dump(label_list, f, ensure_ascii=False, indent=2)

    print("Emotion model training complete.")


def train_safety_model(
    config: TrainConfig,
    output_dir: str,
    custom_dataset_path: Optional[str] = None,
    lexicon_words: Optional[List[str]] = None,
    augment_with_lexicons: bool = False,
    lexicon_neg_mult: int = 3,
):
    print("Preparing safety/behavior dataset...")
    # If user provides a custom dataset CSV/JSONL with columns 'text' and 'label', use it.
    if custom_dataset_path:
        ext = os.path.splitext(custom_dataset_path)[1].lower()
        if ext == ".csv":
            ds = load_dataset("csv", data_files={"train": custom_dataset_path})
        elif ext in [".json", ".jsonl"]:
            ds = load_dataset("json", data_files={"train": custom_dataset_path})
        else:
            raise RuntimeError("Unsupported custom dataset format: " + ext)
        # Expect a 'label' column which is integer or string
        if "validation" in ds:
            train_ds = ds["train"]
            val_ds = ds["validation"]
        else:
            # split
            split = ds["train"].train_test_split(test_size=0.1, seed=config.seed)
            train_ds = split["train"]
            val_ds = split["test"]

        label_list = train_ds.unique("label")
        label_list = sorted(label_list)
    else:
        # fallback: use civil_comments or a generic toxicity dataset if available
        try:
            ds = load_dataset("civil_comments")
            # civil_comments has a 'toxicity' float label, this is only a heuristic mapping
            def map_label(example):
                # thresholds -> safe(0), warning(1), critical(2)
                t = example.get("toxicity", 0.0)
                if t >= 0.8:
                    return {"label": 2}
                elif t >= 0.4:
                    return {"label": 1}
                else:
                    return {"label": 0}

            ds = ds.map(lambda x: {"text": x.get("text", x.get("comment_text")), **map_label(x)})
            split = ds["train"].train_test_split(test_size=0.1, seed=config.seed)
            train_ds = split["train"]
            val_ds = split["test"]
            label_list = ["safe", "warning", "critical"]
        except Exception:
            raise RuntimeError("No toxicity dataset available. Provide --custom-safety-dataset path")

    num_labels = len(label_list)

    # If requested, augment the train dataset with synthetic positive examples
    # derived from provided lexicon words. This helps bootstrap the positive class
    # but is not a substitute for human-labeled examples.
    if augment_with_lexicons and lexicon_words:
        try:
            print(f"Augmenting safety train set with {len(lexicon_words)} lexicon words...")
            # Build synthetic positive examples using short templates
            templates = [
                "You're a {w}.",
                "What a {w}.",
                "Stop being such a {w}.",
                "I can't believe you {w}.",
            ]
            lex_texts = []
            lex_labels = []
            for w in lexicon_words:
                # create 1-2 variants per lexicon word
                for i in range(1 + (len(w) // 8)):
                    t = templates[(i) % len(templates)]
                    lex_texts.append(t.format(w=w))
                    lex_labels.append(1)

            if len(lex_texts) > 0:
                lex_ds = Dataset.from_dict({"text": lex_texts, "label": lex_labels})
                try:
                    train_ds = concatenate_datasets([train_ds, lex_ds])
                    print(f"Train dataset augmented: +{len(lex_texts)} examples")
                except Exception as e:
                    print("Warning: could not concatenate lexicon dataset:", e)
        except Exception as e:
            print("Lexicon augmentation failed:", e)
    # Optionally, lexicon augmentation can be injected by the caller by providing
    # a pre-built lexicon dataset via datasets.concatenate_datasets before this function
    tokenizer = AutoTokenizer.from_pretrained(config.safety_model_name)

    def preprocess(batch):
        enc = tokenizer(batch["text"], truncation=True)
        enc["labels"] = batch["label"]
        return enc

    train_enc = train_ds.map(preprocess, batched=True)
    val_enc = val_ds.map(preprocess, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        config.safety_model_name, num_labels=num_labels
    )

    training_args = TrainingArguments(
        output_dir=os.path.join(output_dir, "safety"),
        evaluation_strategy="epoch",
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        num_train_epochs=config.epochs,
        learning_rate=config.lr,
        seed=config.seed,
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_strategy="steps",
        logging_steps=100,
    )

    metric_acc = evaluate.load("accuracy")
    metric_f1 = evaluate.load("f1")

    def compute_metrics_eval(p):
        preds = np.argmax(p.predictions, axis=1)
        return {
            "accuracy": metric_acc.compute(predictions=preds, references=p.label_ids),
            "f1_macro": metric_f1.compute(predictions=preds, references=p.label_ids, average="macro"),
            "f1_micro": metric_f1.compute(predictions=preds, references=p.label_ids, average="micro"),
        }

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_enc,
        eval_dataset=val_enc,
        tokenizer=tokenizer,
        compute_metrics=compute_metrics_eval,
    )

    trainer.train()
    trainer.save_model(os.path.join(output_dir, "safety"))

    # Save label map
    os.makedirs(os.path.join(output_dir, "safety"), exist_ok=True)
    with open(os.path.join(output_dir, "safety", "label_map.json"), "w", encoding="utf-8") as f:
        json.dump(label_list, f, ensure_ascii=False, indent=2)

    print("Safety model training complete.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--emotion-model", default="roberta-base")
    parser.add_argument("--safety-model", default="roberta-base")
    parser.add_argument("--output-dir", default="./ml-models")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--custom-safety-dataset", type=str, default=None,
                        help="Path to CSV/JSONL safety dataset with 'text' and 'label' columns")
    parser.add_argument("--lexicons", nargs="*", default=None, help="Paths to lexicon txt files to augment safety training")
    parser.add_argument("--augment-with-lexicons", action="store_true", help="Whether to augment safety train set with lexicon-derived synthetic examples")
    parser.add_argument("--skip-emotion", action="store_true", help="Skip emotion model training and run safety training only")
    args = parser.parse_args()

    cfg = TrainConfig(
        emotion_model_name=args.emotion_model,
        safety_model_name=args.safety_model,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        seed=args.seed,
    )

    os.makedirs(cfg.output_dir, exist_ok=True)
    with open(os.path.join(cfg.output_dir, "train_config.json"), "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, indent=2)

    if not args.skip_emotion:
        print("Starting emotion model training...")
        try:
            train_emotion_model(cfg, cfg.output_dir)
        except Exception as e:
            print("Emotion training failed or dataset not available:", e)
    else:
        print("Skipping emotion model training (--skip-emotion provided)")

    print("Starting safety model training...")
    lex_words = None
    if args.lexicons:
        lex_words = load_lexicons(args.lexicons)
    train_safety_model(
        cfg,
        cfg.output_dir,
        custom_dataset_path=args.custom_safety_dataset,
        lexicon_words=lex_words,
        augment_with_lexicons=args.augment_with_lexicons,
    )


if __name__ == "__main__":
    main()
