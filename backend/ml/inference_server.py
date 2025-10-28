"""
FastAPI inference server for the trained toxicity model.

Run with:
  uvicorn inference_server:app --host 0.0.0.0 --port 8001

The server exposes a /predict endpoint that accepts JSON: {"text": "..."}
and returns a JSON with probabilities, predicted labels and a confidence score.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np


class PredictRequest(BaseModel):
    text: str
    threshold: float = 0.5


app = FastAPI(title='Toxicity Inference')

# Set MODEL_DIR env or default
MODEL_DIR = os.environ.get('TOXIC_MODEL_DIR', './models/xlm-toxic')

print('Loading model from', MODEL_DIR)
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

# derive labels from model config if available
LABELS: List[str] = []
if hasattr(model.config, 'id2label') and model.config.id2label:
    LABELS = [model.config.id2label[i] for i in sorted(model.config.id2label.keys(), key=int)]
else:
    # fallback: generic labels
    LABELS = [f'label_{i}' for i in range(model.config.num_labels)]


def predict_text(text: str, threshold: float = 0.5) -> Dict[str, Any]:
    if not text:
        raise ValueError('text empty')
    inputs = tokenizer(text, truncation=True, padding=True, return_tensors='pt')
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits.squeeze(0).cpu()

    # Support both multi-label and single-label
    if model.config.problem_type == 'multi_label_classification' or model.config.num_labels > 1:
        probs = torch.sigmoid(logits).numpy()
        preds = (probs >= threshold).astype(int)
        labels = [LABELS[i] for i, p in enumerate(preds) if p]
        confidence = float(np.max(probs))
        score_map = {LABELS[i]: float(probs[i]) for i in range(len(LABELS))}
        return {'probs': score_map, 'predicted_labels': labels, 'confidence': confidence}
    else:
        probs = torch.softmax(logits, dim=-1).numpy()
        idx = int(np.argmax(probs))
        return {'probs': {LABELS[i]: float(probs[i]) for i in range(len(LABELS))}, 'predicted_label': LABELS[idx], 'confidence': float(probs[idx])}


@app.post('/predict')
def predict(req: PredictRequest):
    try:
        out = predict_text(req.text, req.threshold)
        return {'ok': True, 'result': out}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/health')
def health():
    return {'ok': True}
