# Evaluation

## What is evaluated?

The evaluation target is the fused detection path: calibrated XGBoost probability followed by `FusionEngine` scoring.

## Metric policy

The repository intentionally does not publish a benchmark table without generated, versioned artifacts. Historical graduation-project metrics are not treated as current repository results.

When an experiment is run, report:

- accuracy;
- precision;
- recall;
- F1;
- ROC-AUC;
- false-positive rate;
- confusion matrix;
- selected threshold;
- dataset version/source;
- repository commit;
- experiment date.

## Threshold integrity

Threshold selection must be performed on validation data. The final test split must be used once for the reported estimate after the threshold is frozen.

The earlier implementation selected thresholds on the same held-out split used for reported metrics. That is a methodological weakness because the test labels influenced model selection. The repository documentation treats those results as optimistic and does not present them as unbiased benchmarks.

## Dataset integrity

The current dataset builder uses source-based heuristic labels. Consequently, random row-level splits can still produce optimistic estimates if related sessions or source-specific artifacts appear in both train and test partitions.

A stronger future evaluation should use attacker/session/time-aware grouping and independently validated labels.

## Reproducibility

The repository does not commit raw telemetry, trained models, or generated metrics. A valid evaluation therefore requires local telemetry and a controlled environment.

Recommended workflow:

```bash
python -m ml.prepare_dataset
python -m ml.train_model
python -m evaluation.evaluate_system
```

Do not copy metrics from an earlier run into the README without recording their provenance.
