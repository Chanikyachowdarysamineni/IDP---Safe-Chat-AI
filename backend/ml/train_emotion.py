"""
Fine-tune a transformer for emotion classification (e.g., GoEmotions).

Usage (example):
  python train_emotion.py \
    --model_name_or_path distilbert-base-uncased \
    --output_dir ./models/emotion-distilbert \
    --epochs 3 \
    --batch_size 16

This script downloads the GoEmotions dataset by default if no train_file is provided.
It creates a single-label classifier over the emotion taxonomy provided by the dataset.
"""

import argparse
import logging
import os
from typing import List

import numpy as np
import torch
from datasets import load_dataset
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
    p.add_argument('--model_name_or_path', type=str, default='distilbert-base-uncased')
    p.add_argument('--output_dir', type=str, default='./models/emotion-distilbert')
    p.add_argument('--epochs', type=int, default=3)
    p.add_argument('--batch_size', type=int, default=16)
    p.add_argument('--lr', type=float, default=2e-5)
    p.add_argument('--max_len', type=int, default=128)
    p.add_argument('--dataset', type=str, default='go_emotions')
    return p.parse_args()


def preprocess(dataset, tokenizer, label_list, max_len):
    def map_labels(ex):
        # GoEmotions has 'labels' as a list of ints (multi-label). For simplicity
        # pick the first label when multiple are present to create a single-label
        # multiclass classifier. For production, consider multi-label training.
        labs = ex.get('labels')
        if isinstance(labs, list) and len(labs) > 0:
            ex['label'] = int(labs[0])
        else:
            ex['label'] = 0
        return ex

    dataset = dataset.map(map_labels)

    def tokenize(ex):
        out = tokenizer(ex.get('text') or ex.get('comment_text') or ex.get('content') or '', truncation=True, padding=False, max_length=max_len)
        out['labels'] = ex['label']
        return out

    dataset = dataset.map(tokenize, batched=False)
    return dataset


def main():
    args = parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_name_or_path)

    # Load dataset (GoEmotions) if available
    if args.dataset == 'go_emotions':
        ds = load_dataset('go_emotions')
        # go_emotions splits: train, validation, test
        train_ds = ds['train']
        val_ds = ds['validation']
        label_list = ds['train'].features['labels'].feature.names
    else:
        raise RuntimeError('Only go_emotions dataset is supported by this script currently')

    num_labels = len(label_list)
    logger.info('Emotion labels (%d): %s', num_labels, label_list)

    model = AutoModelForSequenceClassification.from_pretrained(args.model_name_or_path, num_labels=num_labels)

    train_ds = preprocess(train_ds, tokenizer, label_list, args.max_len)
    val_ds = preprocess(val_ds, tokenizer, label_list, args.max_len)

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        evaluation_strategy='steps',
        eval_steps=500,
        save_steps=500,
        learning_rate=args.lr,
        logging_steps=100,
        fp16=torch.cuda.is_available(),
        load_best_model_at_end=True,
        metric_for_best_model='accuracy',
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        from sklearn.metrics import accuracy_score, f1_score
        acc = accuracy_score(labels, preds)
        f1 = f1_score(labels, preds, average='macro')
        return {'accuracy': acc, 'f1_macro': f1}

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
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    logger.info('Emotion model training complete; saved to %s', args.output_dir)


if __name__ == '__main__':
    main()
