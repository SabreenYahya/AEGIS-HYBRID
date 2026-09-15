# Reproducibility

## Environment

Use Python 3.11+ and install the pinned repository requirements:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure telemetry and model paths through `.env` based on `.env.example`.

## Reproduce the canonical pipeline

```bash
python -m ml.prepare_dataset
python -m ml.train_model
python -m pipeline.offline_pipeline
```

The pipeline writes the configured SOC-oriented JSON output. Raw logs and trained artifacts remain local.

## Reproduce evaluation

```bash
python -m evaluation.evaluate_system
```

Record the commit, dataset provenance, environment, and generated metrics together. A metric without provenance is not a useful benchmark artifact.

## Verification checklist

- [ ] Python version recorded.
- [ ] Dependency versions recorded.
- [ ] Dataset source and labeling strategy recorded.
- [ ] Dataset class distribution recorded.
- [ ] Random seed recorded.
- [ ] Train/validation/test sizes recorded.
- [ ] Threshold selected without test labels.
- [ ] Final metrics generated from the frozen test split.
- [ ] Repository commit recorded.
