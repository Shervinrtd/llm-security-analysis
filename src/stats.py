"""Statistical rigor for the experiments: confidence intervals and significance.

Point estimates alone ("model A scored 0.71, B scored 0.68") cannot support a
claim - the difference may be noise. Two tools fix that, both non-parametric so
they make no distributional assumptions about the metrics:

    bootstrap_ci   a confidence interval for any metric, by resampling the
                   per-sample results. Answers "how precise is this number?"
    mcnemar        a paired significance test for two detectors on the SAME
                   samples. Answers "is A actually better than B, or is the gap
                   within noise?" Paired is essential: the models saw identical
                   inputs, so their errors are correlated and an unpaired test
                   would be wrong.

Everything works on per-sample records, so it applies uniformly to the
vulnerability, dependency, secret and malware pillars.
"""
from __future__ import annotations

import math
import random
from typing import Callable, Sequence


# --------------------------------------------------------------- metrics
def binary_counts(preds: Sequence[int], trues: Sequence[int]) -> dict:
    if len(preds) != len(trues):
        raise ValueError("Prediction and truth lengths differ")
    tp = sum(1 for p, t in zip(preds, trues) if p == 1 and t == 1)
    fp = sum(1 for p, t in zip(preds, trues) if p == 1 and t == 0)
    tn = sum(1 for p, t in zip(preds, trues) if p == 0 and t == 0)
    fn = sum(1 for p, t in zip(preds, trues) if p == 0 and t == 1)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def f1(tp, fp, tn, fn) -> float:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * p * r / (p + r) if (p + r) else 0.0


def mcc(tp, fp, tn, fn) -> float:
    num = tp * tn - fp * fn
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return num / den if den else 0.0


def balanced_accuracy(tp, fp, tn, fn) -> float:
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return (tpr + tnr) / 2


METRICS: dict[str, Callable] = {
    "f1": f1, "mcc": mcc, "balanced_accuracy": balanced_accuracy,
    "accuracy": lambda tp, fp, tn, fn: (tp + tn) / max(tp + fp + tn + fn, 1),
    "precision": lambda tp, fp, tn, fn: tp / max(tp + fp, 1),
    "recall": lambda tp, fp, tn, fn: tp / max(tp + fn, 1),
}


# --------------------------------------------------------------- bootstrap
def bootstrap_ci(preds: Sequence[int], trues: Sequence[int], metric: str = "f1",
                 n_boot: int = 2000, alpha: float = 0.05, seed: int = 42) -> dict:
    """Percentile bootstrap CI for a binary metric over paired (pred, true)."""
    fn = METRICS[metric]
    n = len(preds)
    if n == 0:
        return {"metric": metric, "point": 0.0, "ci_low": 0.0, "ci_high": 0.0, "n": 0}
    idx = list(range(n))
    c = binary_counts(preds, trues)
    point = fn(c["tp"], c["fp"], c["tn"], c["fn"])

    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        sample = [idx[rng.randrange(n)] for _ in range(n)]
        bp = [preds[i] for i in sample]
        bt = [trues[i] for i in sample]
        cc = binary_counts(bp, bt)
        vals.append(fn(cc["tp"], cc["fp"], cc["tn"], cc["fn"]))
    vals.sort()
    lo = vals[int((alpha / 2) * n_boot)]
    hi = vals[int((1 - alpha / 2) * n_boot) - 1]
    return {"metric": metric, "point": round(point, 4),
            "ci_low": round(lo, 4), "ci_high": round(hi, 4),
            "ci_width": round(hi - lo, 4), "n": n, "n_boot": n_boot}


# --------------------------------------------------------------- McNemar
def mcnemar(preds_a: Sequence[int], preds_b: Sequence[int],
            trues: Sequence[int]) -> dict:
    """Paired test on two detectors over the SAME samples.

    Compares where they DISAGREE about correctness: b01 = A right & B wrong,
    b10 = A wrong & B right. The exact binomial version is used (no chi-square
    approximation), so it is valid even when the discordant count is small.
    """
    if len(preds_a) != len(preds_b) or len(preds_a) != len(trues):
        raise ValueError("Paired comparison lengths differ")
    correct_a = [int(p == t) for p, t in zip(preds_a, trues)]
    correct_b = [int(p == t) for p, t in zip(preds_b, trues)]
    b01 = sum(1 for a, b in zip(correct_a, correct_b) if a == 1 and b == 0)
    b10 = sum(1 for a, b in zip(correct_a, correct_b) if a == 0 and b == 1)
    n = b01 + b10
    # exact two-sided binomial p-value with p=0.5
    if n == 0:
        p_value = 1.0
    else:
        k = min(b01, b10)
        p_value = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n))
    acc_a = sum(correct_a) / len(trues) if trues else 0.0
    acc_b = sum(correct_b) / len(trues) if trues else 0.0
    return {"a_only_correct": b01, "b_only_correct": b10,
            "accuracy_a": round(acc_a, 4), "accuracy_b": round(acc_b, 4),
            "p_value": p_value,
            "significant_at_05": p_value < 0.05,
            "better": ("A" if acc_a > acc_b else "B" if acc_b > acc_a else "tie")}


def holm_adjusted(pvals: dict[str, float]) -> dict[str, float]:
    ordered = sorted(pvals.items(), key=lambda kv: kv[1])
    out, previous = {}, 0.0
    for i, (name, p) in enumerate(ordered):
        if not 0 <= p <= 1:
            raise ValueError("p-values must be between zero and one")
        previous = max(previous, min(1.0, p * (len(ordered) - i)))
        out[name] = previous
    return out


def clustered_accuracy_permutation(preds_a, preds_b, trues, clusters, n_perm=10000, seed=42):
    """Swap system labels for whole repositories, preserving within-group errors.

    A post-hoc paired randomisation sensitivity test; assumes exchangeability
    of the two systems under the null at the repository level.
    """
    if not (len(preds_a) == len(preds_b) == len(trues) == len(clusters)):
        raise ValueError("Clustered comparison lengths differ")
    grouped = {}
    for a,b,t,c in zip(preds_a,preds_b,trues,clusters):
        grouped[c] = grouped.get(c,0) + int(a == t) - int(b == t)
    diffs = [v for v in grouped.values() if v]
    observed = abs(sum(diffs))
    rng = random.Random(seed)
    exceed = sum(abs(sum(v if rng.getrandbits(1) else -v for v in diffs)) >= observed for _ in range(n_perm))
    return {"p_value":(exceed+1)/(n_perm+1),"n_permutations":n_perm,"seed":seed,
            "n_clusters":len(grouped),"nonzero_clusters":len(diffs),
            "accuracy_difference":sum(diffs)/len(trues) if trues else None}


def holm_bonferroni(pvals: dict[str, float], alpha: float = 0.05) -> dict[str, bool]:
    """Multiple-comparison correction: when many pairs are tested, some clear
    0.05 by chance. Holm controls that without being as harsh as Bonferroni."""
    ordered = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(ordered)
    out, still = {}, True
    for i, (name, p) in enumerate(ordered):
        thresh = alpha / (m - i)
        if still and p <= thresh:
            out[name] = True
        else:
            still = False
            out[name] = False
    return out


if __name__ == "__main__":
    rng = random.Random(0)
    trues = [rng.randint(0, 1) for _ in range(300)]
    # A: 85% accurate, B: 78% accurate, correlated
    preds_a = [t if rng.random() < 0.85 else 1 - t for t in trues]
    preds_b = [t if rng.random() < 0.78 else 1 - t for t in trues]
    print("bootstrap F1 (A):", bootstrap_ci(preds_a, trues, "f1", n_boot=500))
    print("mcnemar A vs B :", mcnemar(preds_a, preds_b, trues))
