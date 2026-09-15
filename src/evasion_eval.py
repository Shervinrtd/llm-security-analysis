"""Adversarial-evasion experiment: how much does obfuscation defeat each detector?

Tests the objective's central claim directly. Take the malicious samples each
detector CATCHES, obfuscate them (semantics preserved, surface hidden), and
re-run detection. The evasion rate is the fraction of previously-caught samples
that now slip through:

    evasion = (caught_original - caught_obfuscated) / caught_original

A signature/rule detector (GuardDog's YARA) keys on surface tokens, so the
prediction is that it evades heavily. A semantic reader (the LLM) reasons about
what the code DOES, so the prediction is that it evades less. Whichever way it
falls is a real result: if the LLM also collapses, that is the objective's
"challenges remain regarding adversarial evasion", measured rather than assumed.

The baseline (GuardDog) is free, so it always runs. The LLM pass is opt-in.

    python src/evasion_eval.py --limit 60                       # baseline only
    python src/evasion_eval.py --with-llm --model local-qwen-coder --limit 40
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C
import obfuscate as OB
import malware_evaluate as MAL

RESULTS = C.DATA / "results"
BENCH = C.PROCESSED / "malware_benchmark.jsonl"


def llm_flags_malicious(provider, content: str, filename: str, strategy: str) -> bool:
    s = {"filename": filename, "content": content}
    sysmsg, user = (MAL.prompt_triage if strategy == "triage"
                    else MAL.prompt_zero_shot)(s)
    rep = provider.generate(sysmsg, user)
    mal, _tech, _ok = MAL.parse_reply(rep.text)
    return bool(mal)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--level", type=int, default=3, help="obfuscation strength 1-3")
    ap.add_argument("--with-llm", action="store_true")
    ap.add_argument("--model", default="local-qwen-coder")
    ap.add_argument("--strategy", default="zero_shot")
    ap.add_argument("--benign-control", type=int, default=25,
                    help="how many benign samples to obfuscate as a false-positive "
                         "control (0 to skip); requires --with-llm")
    ap.add_argument("--out", default=str(RESULTS / "evasion_predictions.jsonl"))
    args = ap.parse_args()

    if not BENCH.exists():
        sys.exit(f"missing {BENCH} - run malware_build.py first")
    rows = [json.loads(l) for l in BENCH.open(encoding="utf-8") if l.strip()]
    mal = [r for r in rows if r.get("is_malicious")]
    if args.limit:
        mal = mal[:args.limit]

    provider = None
    if args.with_llm:
        import models as M
        provider = M.get(args.model)
        if not provider.is_available():
            sys.exit(f"model '{args.model}' unavailable. Have: {M.available()}")

    # CONTROL: does the LLM flag obfuscated BENIGN code as malicious? Without this
    # a high "detection after obfuscation" is meaningless - it cannot tell reading
    # the malicious behaviour apart from keying on obfuscation itself.
    benign_control = None
    if provider is not None and args.benign_control:
        benign = [r for r in rows if not r.get("is_malicious")][:args.benign_control]
        fp_o = fp_b = 0
        for i, s in enumerate(benign, 1):
            fn = s.get("filename", "sample.py")
            fp_o += llm_flags_malicious(provider, s["content"], fn, args.strategy)
            obf = OB.obfuscate(s["content"], level=args.level, seed=i)
            fp_b += llm_flags_malicious(provider, obf, fn, args.strategy)
        n = len(benign)
        benign_control = {
            "n": n,
            "false_positive_original": round(fp_o / n, 4) if n else 0,
            "false_positive_obfuscated": round(fp_b / n, 4) if n else 0,
        }

    records = []
    t0 = time.time()
    for i, s in enumerate(mal, 1):
        orig = s["content"]
        obf = OB.obfuscate(orig, level=args.level, seed=i)
        rec = {
            "sample_id": s.get("sample_id"), "technique": s.get("technique"),
            "language": s.get("language"),
            "yara_orig": MAL.yara_flag(orig),
            "yara_obf": MAL.yara_flag(obf),
            "grew_chars": len(obf) - len(orig),
        }
        if provider is not None:
            fn = s.get("filename", "sample.py")
            rec["llm_orig"] = llm_flags_malicious(provider, orig, fn, args.strategy)
            rec["llm_obf"] = llm_flags_malicious(provider, obf, fn, args.strategy)
        records.append(rec)
        if i % 20 == 0:
            print(f"  {i}/{len(mal)} processed ...")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    def evasion(prefix):
        caught = [r for r in records if r.get(f"{prefix}_orig")]
        if not caught:
            return None
        still = [r for r in caught if r.get(f"{prefix}_obf")]
        return {
            "detection_original": round(sum(1 for r in records if r.get(f"{prefix}_orig")) / len(records), 4),
            "detection_obfuscated": round(sum(1 for r in records if r.get(f"{prefix}_obf")) / len(records), 4),
            "n_caught_original": len(caught),
            "n_still_caught": len(still),
            "evasion_rate": round((len(caught) - len(still)) / len(caught), 4),
        }

    summary = {
        "n_samples": len(records), "obfuscation_level": args.level,
        "guarddog_yara": evasion("yara"),
        "wall_s": round(time.time() - t0, 1),
    }
    if args.with_llm:
        summary["llm"] = {"model": args.model, "strategy": args.strategy,
                          **(evasion("llm") or {})}
        if benign_control:
            summary["llm"]["benign_obfuscation_control"] = benign_control

    # per-technique evasion for the baseline, to see which hides best
    techs = sorted({r["technique"] for r in records})
    summary["yara_evasion_by_technique"] = {}
    for t in techs:
        sub = [r for r in records if r["technique"] == t]
        caught = [r for r in sub if r["yara_orig"]]
        if caught:
            still = sum(1 for r in caught if r["yara_obf"])
            summary["yara_evasion_by_technique"][t] = {
                "caught_original": len(caught),
                "evasion_rate": round((len(caught) - still) / len(caught), 4)}

    spath = RESULTS / "evasion_summary.json"
    spath.write_text(json.dumps(summary, indent=1), encoding="utf-8")

    print("\n" + "=" * 70)
    print(f"ADVERSARIAL EVASION  (obfuscation level {args.level}, {len(records)} malicious samples)")
    print("=" * 70)
    g = summary["guarddog_yara"]
    if g:
        print(f"\n  GuardDog YARA (signature baseline):")
        print(f"    detection before obfuscation : {g['detection_original']*100:.1f}%")
        print(f"    detection after  obfuscation : {g['detection_obfuscated']*100:.1f}%")
        print(f"    EVASION RATE                 : {g['evasion_rate']*100:.1f}%  "
              f"({g['n_caught_original'] - g['n_still_caught']}/{g['n_caught_original']} caught samples slipped through)")
    if "llm" in summary and summary["llm"].get("evasion_rate") is not None:
        L = summary["llm"]
        print(f"\n  {L['model']} (semantic):")
        print(f"    detection before obfuscation : {L['detection_original']*100:.1f}%")
        print(f"    detection after  obfuscation : {L['detection_obfuscated']*100:.1f}%")
        print(f"    EVASION RATE                 : {L['evasion_rate']*100:.1f}%  "
              f"({L['n_caught_original'] - L['n_still_caught']}/{L['n_caught_original']} caught samples slipped through)")
        bc = L.get("benign_obfuscation_control")
        if bc:
            print(f"\n  CONTROL - obfuscated BENIGN code flagged malicious by {L['model']}:")
            print(f"    before obfuscation : {bc['false_positive_original']*100:.0f}%")
            print(f"    after  obfuscation : {bc['false_positive_obfuscated']*100:.0f}%")
            if bc["false_positive_obfuscated"] > bc["false_positive_original"] + 0.15:
                print("    => the model keys on obfuscation ITSELF, not on the behaviour:")
                print("       its high 'detection' of obfuscated malware is largely this,")
                print("       and it cries wolf on obfuscated benign code.")
    print(f"\n  summary -> {spath}")


if __name__ == "__main__":
    main()
