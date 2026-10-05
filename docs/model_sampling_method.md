# URL-only model and sampling method, version 2

## Preserved base

GitHub base: 9acd015e20bf6a180cc2080e711b3115e3fec01b. Files were verified against
Git blob hashes before modification. Local history is preserved separately. Original
cleaning, 18 features, acquisition evidence, model families, search grids and domain
split objective remain. No new real dataset was sampled or trained in this revision.

## Sampling and randomness

The original preparation already used seeded random sampling. Version 2 makes
duplicate representative selection independent of input order using fixed legacy
source priority (PhishTank/OpenPhish/Tranco, then other sources), then raw URL.
Conflicting labels are removed first; rejected rows retain alternate provenance.
Canonical candidate pools are sampled uniformly without replacement within class
using independent streams derived from the sampling seed. Canonically sorted output
does not make sample membership nonrandom. Uniform URL sampling is not uniform domain
sampling. Version 2 can select different records than version 1 with the same seed;
old datasets must not be silently regenerated.

The sampling manifest saves algorithm version, class seeds, input hashes, candidate
pool hash, requested/actual counts, shortfalls and dataset hash. A new seed plan can
be generated once from system entropy or an explicit master seed. It separates
sampling, held-out test, development and model seeds. Record it before outcomes;
never regenerate plans to improve scores. Fixed seeds support reproducibility and
do not eliminate randomness or source bias.

Legacy test seed 2025 and development seeds 11/23/37/53/71 remain defaults. Model
seed is held fixed across splits to isolate split variation. LR's default lbfgs
solver is deterministic for fixed inputs; random_state does not make it stochastic.
The tree and Random Forest use the recorded model seed; Random Forest also fixes
single-process fitting for reproducible baseline execution. Five-seed SD describes
overlapping development splits, not independent confidence intervals or a complete
estimator-seed study.

The existing split search considers 500 random group permutations and selects on
size/class balance only. It is constrained group randomization, not uniform sampling
over every possible split. A cumulative-array implementation now preserves that
objective and selected groups, verified against the previous loop. Each seed's split
is cached and shared across models, parameters and feature sets; test membership
is identical across seeds. All assignments, sample IDs, domain groups and seeds are saved.

## Models and evaluation

| Model | Search | Strength | Limitation |
|---|---|---|---|
| Logistic Regression | C 0.1/1/10, max_iter 2000 | Compact linear baseline; inspectable coefficients | Misses direct nonlinear interactions; correlated features complicate interpretation |
| Decision Tree | depth 3/5/8/unrestricted, leaf size 2/10 | Nonlinear interactions; shallow rules are readable | Overfitting/sample instability; impurity importance bias |
| Random Forest | 100 trees; depth 12/unrestricted; sqrt features | Additional nonlinear ensemble baseline; less sensitive than one tree to a single split | Less interpretable; impurity importance can still be biased and training is slower |

LR uses training-only median imputation and scaling; the tree uses imputation
without scaling. Convergence warnings stop fitting. Selection remains mean validation
F1 with deterministic tie-breaking. Save every seed, mean/SD, selected rows and paired
tree-minus-LR F1 differences. Threshold remains 0.5; phishing is 1. Record accuracy,
precision, recall, F1, FPR, ROC-AUC, average precision and confusion counts.

The loader now rejects fractional labels, inconsistent raw/clean URLs and stored PSL
domains, as well as existing duplicate/conflict checks. Training rows use canonical
sample-ID order. Unknown model names fail explicitly. The default run stops after
development; feature diagnostics exclude test. Finalization requires the completed
development directory and matching data, code, dependency versions, features, seeds,
grids and threshold. It verifies replayed split/selection/validation checksums before
test evaluation. Evidence cannot be overwritten. These are audit guards, not access
controls; one-time test use still depends on the research protocol.

## Validation status

Tests cover existing behavior, random replay, input-order invariance, group isolation,
16/18/21 schemas, missing data, train-only preprocessing and saved-model inference.
Reserved example domains are software fixtures only. Their scores are not research
performance evidence and do not establish that either model is better.

## Primary references

- [scikit-learn 1.7: leakage and randomness](https://scikit-learn.org/1.7/common_pitfalls.html).
- [LogisticRegression](https://scikit-learn.org/1.7/modules/generated/sklearn.linear_model.LogisticRegression.html).
- [Decision Trees](https://scikit-learn.org/1.7/modules/tree.html).
- [Feature hypotheses and research references](feature_rationale.md).

## Assignment 03 Phase 1 extension

The URL baseline now includes Random Forest as the required additional baseline
family before DOM work begins. The primary protocol remains domain-grouped and
development-only. A separate Phase 1 diagnostic reuses the selected development
hyperparameters to examine training-size stability and, optionally, a conventional
random URL split. These diagnostics never score the held-out test rows and do not
replace the domain-grouped protocol. Random URL results report train/validation
domain overlap explicitly so any optimistic effect is visible rather than hidden.
