ML training & serving guide
===========================

This folder contains scripts to train and serve models for toxicity and emotion detection.

Prerequisites
-------------

- Python 3.9+ (3.10/3.11 recommended)
- CUDA-enabled GPU for faster training (optional)
- Install dependencies (inside this folder or a venv):

```bash
python -m pip install -r requirements.txt
```

Training
--------

1. Train toxicity model (example):

```bash
python train_toxicity.py \
  --model_name_or_path xlm-roberta-base \
  --train_file /path/to/train.csv \
  --validation_file /path/to/valid.csv \
  --label_cols toxic,insult,threat \
  --multi_label \
  --output_dir ./models/xlm-toxic \
  --epochs 3 \
  --batch_size 16
```

2. Train emotion model using the GoEmotions dataset (script will download it automatically):

```bash
python train_emotion.py --model_name_or_path distilbert-base-uncased --output_dir ./models/emotion-distilbert --epochs 3 --batch_size 16
```

Tips for better performance
---------------------------

- Use larger datasets and clean labels. Consider a human-in-the-loop review to fix noisy labels.
- Use data augmentation: paraphrasing, back-translation, and contextual synonym replacement.
- Use class re-balancing or focal loss for imbalanced labels.
- Fine-tune with mixed precision (fp16) on GPU.
- Monitor validation metrics (macro-F1) and use early stopping.
- After training, export to ONNX and apply quantization (use `optimum` or `onnxruntime.quantization`) to speed up server inference.

Serving
-------

There's an example FastAPI inference server at `inference_server.py`. Start it with:

```bash
uvicorn inference_server:app --host 0.0.0.0 --port 8001
```

Set the environment variable `TOXIC_MODEL_DIR` to point to your trained toxicity model directory before starting the server.

Integration with the application
-------------------------------

The frontend `ml-analyzer.ts` attempts to call `/api/analyze` (server-side inference). You can either:

- Extend the existing Node backend to forward requests to this FastAPI service, or
- Re-implement a lightweight inference endpoint in Node that loads an ONNX-quantized model.

Active learning and continuous improvement
----------------------------------------

1. Collect human feedback (annotations) from users when they report incorrect predictions.
2. Periodically aggregate these annotations and create a small, high-quality validation set.
3. Retrain the model with the new data and deploy the updated model using a canary rollout.

License & Data
--------------
Be mindful of dataset licenses (GoEmotions and others). Ensure your usage complies with terms.

Quick start (included helper scripts)
------------------------------------

This repository includes `train_pipeline.py` (for emotion + safety training) and
`make_safety_dataset_from_lexicons.py` (to create a synthetic CSV from lexicon files).

Example PowerShell commands (from `backend/ml`):

```powershell
# create and activate a venv
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -U pip

# install cleaned ML requirements
pip install -r requirements_ml.txt

# generate a safety CSV from lexicons (place en.txt and hi.txt here or pass full paths)
python make_safety_dataset_from_lexicons.py --lexicons en.txt hi.txt --out safety_lexicons.csv --neg-mult 3

# train both models (or use --skip-emotion to train safety-only)
python train_pipeline.py --custom-safety-dataset safety_lexicons.csv --lexicons en.txt hi.txt --augment-with-lexicons --emotion-model distilroberta-base --safety-model distilroberta-base --output-dir ./ml-models --epochs 3 --batch-size 8

# safety-only run (skip emotion training)
python train_pipeline.py --custom-safety-dataset safety_lexicons.csv --skip-emotion --safety-model distilroberta-base --output-dir ./ml-models --epochs 3 --batch-size 8
```

If you want me to generate `safety_lexicons.csv` inside this workspace, upload `en.txt` and `hi.txt` to `backend/ml/` and I will create the CSV and preview it for you.
