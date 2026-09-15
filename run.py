"""One-command launcher for the whole project.

If you don't know where to start, run this file:

    python run.py

It checks whether an API key is set, tells you exactly what to do if not, and
otherwise runs a small pilot of every part of the study and prints a summary.
Everything it runs is capped small and cached, so it is cheap and safe to
re-run.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
PY = sys.executable
sys.path.insert(0, str(SRC))

import models as M   # noqa: E402  (after sys.path setup)

# ----------------------------------------------------------------------------
SETUP_HELP = """
============================================================================
  ONE STEP TO GO:  pick a model
============================================================================

OPTION A - a LOCAL model (no API key, no rate limits, works offline)

     1. Install Ollama once:      winget install Ollama.Ollama
     2. Download a code model:    ollama pull qwen2.5-coder:7b
     3. Leave it running:         ollama serve

   The project then picks it up automatically as 'local-qwen-coder'.
   Nothing to paste, nothing to sign up for, and no daily quota.

OPTION B - a free CLOUD key (faster, but capped per day)

     1. Open  https://aistudio.google.com/apikey  and sign in (free).
     2. Click "Create API key" and copy the string.
     3. In this folder create a file named  .env  containing one line:
              GEMINI_API_KEY=your_key_here

   Other free providers work the same way:
        GROQ_API_KEY  ·  OPENROUTER_API_KEY  ·  MISTRAL_API_KEY

Then run this launcher again:     python run.py
============================================================================
"""

# each step: (label, script, extra args). Small limits keep the pilot cheap.
PILOT_STEPS = [
    ("Pillar 1 - Vulnerabilities",
     "src/evaluate.py",
     ["--data", "data/processed/test.jsonl", "--train", "data/processed/train.jsonl",
      "--strategies", "zero_shot,cot_8step", "--limit", "20"]),
    ("Pillar 4 - Dependencies",
     "src/deps_evaluate.py",
     ["--strategies", "zero_shot,cot", "--limit", "20"]),
    ("Pillar 3 - Secrets",
     "src/secrets_evaluate.py",
     ["--strategies", "zero_shot,context", "--limit", "20"]),
    ("Pillar 2 - Malware",
     "src/malware_evaluate.py",
     ["--strategies", "zero_shot,triage", "--limit", "20"]),
]


def pick_model() -> str | None:
    avail = [m for m in M.available() if m != "stub"]
    return avail[0] if avail else None


def run_step(label: str, script: str, model: str, extra: list[str]) -> bool:
    print("\n" + "=" * 76)
    print(f"  {label}   (model: {model})")
    print("=" * 76)
    cmd = [PY, str(ROOT / script), "--models", model] + extra
    try:
        subprocess.run(cmd, cwd=str(ROOT), check=False)
        return True
    except Exception as e:
        print(f"  !! could not run {script}: {e}")
        return False


def main() -> None:
    print("\n  LLM Security Analysis — project launcher\n")

    model = pick_model()
    if model is None:
        print(SETUP_HELP)
        # still offer the offline self-test so the user sees it works
        print("Meanwhile, here is the OFFLINE self-test (fake model, checks the machinery):\n")
        run_step("Self-test (offline stub)", "src/evaluate.py", "stub",
                 ["--data", "data/processed/test.jsonl", "--train", "data/processed/train.jsonl",
                  "--strategies", "zero_shot", "--limit", "10"])
        print("\nThe machinery works. Add a free key (steps above) and run  python run.py  again.")
        return

    print(f"  Found a working model: {model}")
    print("  Running a small pilot across all four pillars (20 samples each).")
    print("  This is capped and cached, so it is cheap and safe to re-run.\n")

    ok = 0
    for label, script, extra in PILOT_STEPS:
        if not (ROOT / script).exists():
            print(f"  (skipping {label}: {script} not found)")
            continue
        if run_step(label, script, model, extra):
            ok += 1

    print("\n" + "=" * 76)
    print(f"  PILOT COMPLETE — {ok}/{len(PILOT_STEPS)} pillars ran with model '{model}'.")
    print("  Detailed results are saved under  data/results/ .")
    print("=" * 76)
    print("""
  Next steps when you are happy with the pilot:
    * raise --limit (or drop it) in each command to run the full benchmark
    * add more models by setting more keys, then list them:
          python src/evaluate.py --models gemini-flash,groq-llama ...
    * try a whole repository:
          python src/repo_analyze.py --repo <path-to-a-project> --model %s
""" % model)


if __name__ == "__main__":
    main()
