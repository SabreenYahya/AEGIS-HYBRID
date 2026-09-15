# ML Methodology

## Model

The canonical classifier is XGBoost wrapped with `CalibratedClassifierCV` using isotonic calibration. Training is implemented in `ml/train_model.py`.

## Features

The model uses behavioral features including event volume, duration, event rate, inter-arrival timing, burstiness, stage entropy/transitions, risk density, command behavior, IP/port fan-out, and binary behavioral flags.

The feature list is explicitly persisted with the model artifact so runtime inference can align columns with the training contract.

## Labeling caveat

`ml/prepare_dataset.py` does not produce ground-truth labels. Cowrie sessions are labeled as attacks, while Suricata labels are derived from alert-ratio thresholds. This introduces source/label correlation and can cause the model to learn telemetry-source artifacts.

Therefore the current ML results should be interpreted as **research measurements on a heuristic labeling strategy**, not proof of generalized malicious-behavior detection.

## Split and thresholding

The training workflow uses a deterministic stratified split. Threshold selection must use validation data rather than the final test set. The test set is reserved for the final metric calculation.

This separation matters because choosing a threshold after observing test labels makes the test set part of model selection and inflates apparent performance.

## Calibration

Probability calibration is applied with isotonic regression through scikit-learn's calibrated classifier wrapper. Calibration quality should be measured separately from classification discrimination in future experiments.

## Reproducibility requirements

Record at minimum:

- repository commit/tag;
- Python and dependency versions;
- dataset source and labeling strategy;
- random seed;
- train/validation/test counts;
- selected threshold;
- model configuration;
- evaluation metrics.

No new performance number should be published without a reproducible dataset and a documented experiment.
