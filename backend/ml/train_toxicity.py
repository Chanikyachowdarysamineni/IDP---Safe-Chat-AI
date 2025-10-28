"""
Fine-tune a multilingual transformer for multi-label toxicity detection.

Usage (example):
  python train_toxicity.py \
    --model_name_or_path xlm-roberta-base \
    --output_dir ./models/xlm-toxic \
    --train_file /path/to/train.csv \
    --validation_file /path/to/valid.csv \
    --epochs 3 \
    --batch_size 16

Notes:
- The script supports providing CSV/JSONL files with a `text` column and one or more label columns.
- For multilingual support use a multilingual model such as `xlm-roberta-base` or `mdeberta-v3-base`.
- For production/low-latency consider exporting to ONNX / quantization after training.
"""

import argparse
import logging
import os
from typing import List

import numpy as np
from datasets import load_dataset, Dataset, DatasetDict, concatenate_datasets
from sklearn.preprocessing import MultiLabelBinarizer
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--model_name_or_path', type=str, default='xlm-roberta-base')
    p.add_argument('--train_file', type=str, default=None, help='CSV/JSONL train file with columns: text,labels or separate label columns')
    p.add_argument('--validation_file', type=str, default=None)
    p.add_argument('--output_dir', type=str, default='./models/xlm-toxic')
    p.add_argument('--epochs', type=int, default=3)
    p.add_argument('--batch_size', type=int, default=16)
    p.add_argument('--lr', type=float, default=2e-5)
    p.add_argument('--max_len', type=int, default=256)
    p.add_argument('--label_cols', type=str, default='', help='Comma-separated label column names if using separate columns')
    p.add_argument('--multi_label', action='store_true', help='Treat as multi-label classification (default: single label)')
    return p.parse_args()


def load_local_file(file_path: str):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ('.csv', '.tsv'):
        return load_dataset('csv', data_files=file_path)
    if ext in ('.json', '.jsonl'):
        return load_dataset('json', data_files=file_path)
    raise ValueError('Unsupported file format: ' + ext)


def prepare_datasets(train_file, validation_file, label_cols: List[str], multi_label: bool):
    # User may provide train/valid files. Each file must contain a `text` column
    # and either `labels` (comma-separated) or individual label columns.
    ds_train = None
    ds_val = None
    if train_file:
        ds_train = load_local_file(train_file)['train'] if 'train' in load_local_file(train_file) else load_local_file(train_file)
        # load_dataset returns a DatasetDict for some loaders; handle gracefully
        if isinstance(ds_train, dict) and 'train' in ds_train:
            ds_train = ds_train['train']
    if validation_file:
        ds_val = load_local_file(validation_file)['train'] if 'train' in load_local_file(validation_file) else load_local_file(validation_file)
        if isinstance(ds_val, dict) and 'train' in ds_val:
            ds_val = ds_val['train']

    # If label_cols provided, create labels column as list (for multilabel) or single label
    if label_cols:
        cols = [c.strip() for c in label_cols.split(',') if c.strip()]

        def to_labels(example):
            if multi_label:
                lab = [c for c in cols if example.get(c)]
                example['labels'] = lab
            else:
                # take first positive or fallback to first col
                for c in cols:
                    if example.get(c):
                        example['labels'] = c
                        break
                else:
                    example['labels'] = None
            return example

        if ds_train is not None:
            ds_train = ds_train.map(to_labels)
        if ds_val is not None:
            ds_val = ds_val.map(to_labels)

    return ds_train, ds_val


def build_label_binarizer(dataset: Dataset, multi_label: bool):
    # Build label set from dataset['labels'] which may be list or string
    all_labels = set()
    for ex in dataset:
        labs = ex.get('labels')
        if labs is None:
            continue
        if isinstance(labs, list):
            all_labels.update(labs)
        else:
            all_labels.add(labs)
    labels = sorted(list(all_labels))
    logger.info('Found labels: %s', labels)
    mlb = MultiLabelBinarizer(classes=labels) if multi_label else None
    return labels, mlb


def preprocess_and_tokenize(ds, tokenizer, labels_list, mlb, max_len, multi_label: bool):
    def _map(ex):
        text = ex.get('text') or ex.get('content') or ex.get('message') or ''
        if multi_label:
            labs = ex.get('labels') or []
            binlab = mlb.transform([labs])[0].astype(float)
            ex['label_ids'] = binlab.tolist()
        else:
            lab = ex.get('labels')
            ex['label_ids'] = labels_list.index(lab) if lab in labels_list else -1
        return ex

    ds = ds.map(_map)

    def tok(ex):
        out = tokenizer(ex.get('text') or ex.get('content') or '', truncation=True, padding=False, max_length=max_len)
        out['label_ids'] = ex['label_ids']
        return out

    ds = ds.map(tok, batched=False)
    return ds


def main():
    args = parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_name_or_path)

    ds_train, ds_val = prepare_datasets(args.train_file, args.validation_file, args.label_cols, args.multi_label)

    if ds_train is None:
        raise RuntimeError('No training data provided')

    # Build label set for multi-label or single-label
    labels_list, mlb = build_label_binarizer(ds_train, args.multi_label)
    num_labels = len(labels_list) if args.multi_label else max(1, len(labels_list))

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name_or_path,
        num_labels=num_labels,
        problem_type='multi_label_classification' if args.multi_label else None,
    )

    # Preprocess
    train_ds = preprocess_and_tokenize(ds_train, tokenizer, labels_list, mlb, args.max_len, args.multi_label)
    eval_ds = preprocess_and_tokenize(ds_val, tokenizer, labels_list, mlb, args.max_len, args.multi_label) if ds_val is not None else None

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        evaluation_strategy='steps' if eval_ds is not None else 'no',
        eval_steps=500,
        save_steps=500,
        learning_rate=args.lr,
        logging_steps=100,
        fp16=torch.cuda.is_available(),
        load_best_model_at_end=True if eval_ds is not None else False,
        metric_for_best_model='loss',
    )

    # Define compute_metrics for multi-label (use micro/macro F1 etc)
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        if args.multi_label:
            probs = torch.sigmoid(torch.from_numpy(logits)).numpy()
            preds = (probs >= 0.5).astype(int)
            from sklearn.metrics import f1_score, precision_score, recall_score
            f1 = f1_score(labels, preds, average='macro')
            precision = precision_score(labels, preds, average='macro', zero_division=0)
            recall = recall_score(labels, preds, average='macro', zero_division=0)
            return {'f1_macro': f1, 'precision_macro': precision, 'recall_macro': recall}
        else:
            preds = np.argmax(logits, axis=-1)
            from sklearn.metrics import accuracy_score
            return {'accuracy': accuracy_score(labels, preds)}

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics if eval_ds is not None else None,
    )

    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    logger.info('Training complete. Model and tokenizer saved to %s', args.output_dir)


if __name__ == '__main__':
    main()
