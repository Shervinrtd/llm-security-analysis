# Scientific scale-up — how to run the experiments

This is the recipe for turning the platform into publishable results. Everything
here is **resumable**: every model answer is cached on disk by content hash, so a
run that dies on a rate limit or a closed laptop costs nothing to restart — just
run the same command again and it skips what's done.

---

## 0. One-time: pick your models

You have two free models ready now:

| Model | Vendor | Cost | Notes |
|---|---|---|---|
| `local-qwen-coder` | Alibaba | **free, unlimited** | runs on your GPU, no key, no rate limit |
| `gemini-flash` | Google | free daily quota | already keyed |

Add a **Meta** model (the objective names Meta) for a proper cross-vendor result:

- Free key at <https://console.groq.com/keys>, paste it in the app or add
  `GROQ_API_KEY=...` to `.env`, then `groq-llama` (Llama 3.3 70B) is available.

**Rule of thumb:** do the heavy lifting on `local-qwen-coder` (free, unlimited).
Use cloud models on the smaller pillars, or overnight, because their free tiers
are rate-limited.

---

## 1. The one-command path

```bash
python run_experiments.py --models local-qwen-coder --scale pilot
```

Scales:

| `--scale` | Vuln samples | Pillar samples | Repo cases | Use it for |
|---|---|---|---|---|
| `pilot` | 60 | 60 | 8 | first sanity pass (~15 min local) |
| `medium` | 600 | 300 | 30 | a defensible experiment |
| `full` | all 6,302 | all | 60 | the final numbers (long — local model, overnight) |

Add models as you get keys:

```bash
python run_experiments.py --models local-qwen-coder,gemini-flash,groq-llama --scale medium
```

It runs all four pillars + the repo benchmark, then computes statistics and
interpretability automatically. Re-run the same line any time to resume/extend.

---

## 2. Or run pillars individually

Each is cached and takes `--limit` (omit for the full set) and `--models`:

```bash
python src/evaluate.py --models local-qwen-coder,gemini-flash --strategies zero_shot,few_shot,cot_8step,dataflow --limit 600
```
```bash
python src/deps_evaluate.py --models local-qwen-coder,gemini-flash --strategies zero_shot,cot
```
```bash
python src/secrets_evaluate.py --models local-qwen-coder,gemini-flash --strategies zero_shot,context
```
```bash
python src/malware_evaluate.py --models local-qwen-coder,gemini-flash --strategies zero_shot,triage
```

---

## 3. The statistics (this is what makes it a paper)

After any run, produce confidence intervals, the per-language breakdown, and
pairwise significance tests:

```bash
python src/analyze_results.py --pred data/results/predictions.jsonl
```

It reports, per model/strategy:
- **F1 / MCC / balanced accuracy with 95% bootstrap CIs** — so a number has error bars
- **per-language F1** — the reason four languages were chosen
- **McNemar pairwise tests, Holm-corrected** — whether A really beats B or it's noise

---

## 4. The specialised experiments (already built)

```bash
# repository-level detection on real CVE commits
python src/repo_bench_eval.py --model local-qwen-coder --limit 60

# interpretability of explanations (grounding, hallucination rate)
python src/interpretability_eval.py --pred data/results/predictions.jsonl

# adversarial evasion — obfuscate malware, measure detection drop (with control)
python src/evasion_eval.py --with-llm --model local-qwen-coder --limit 80 --benign-control 25
```

---

## 5. Suggested plan for the paper

1. **Pilot** on `local-qwen-coder` to confirm everything runs end-to-end.
2. **Medium** across all three vendors (local Alibaba, Google, Meta) — the main
   cross-model / cross-strategy / cross-language table, with CIs and significance.
3. **Full** vuln pillar on `local-qwen-coder` overnight for the headline number.
4. The three specialised experiments (repo-level, interpretability, evasion) once
   each — they need no scale, just the run.
5. `analyze_results.py` produces the tables; the false-positive corpus
   (`fp_corpus.py`) supplies the precision headline on trusted code.

Every result file lands in `data/results/`. Nothing here is destructive, and
`python selftest.py` (10/10) confirms the machinery before you trust a number.
