"""Pillar 3, step 1 - build a hardcoded-secrets benchmark.

Why synthetic
-------------
SecretBench (Basak et al., MSR 2023) is the reference dataset here, but its
contents are access-controlled behind a signed research agreement, and it holds
real secrets harvested from public repositories - some potentially still live.
We therefore do not use its data. We reuse its *category taxonomy* (cited) and
generate our own values.

This is not a compromise for our research question. We are asking:

    can a model tell a REAL credential from a placeholder, test fixture,
    or documentation example?

That depends on the token's format and its surrounding context, not on whether
the key actually authenticates. Synthetic generation gives exact ground truth,
zero ethical risk, and a benchmark we can publish - which SecretBench cannot be.

All "real" secrets are randomly generated from a fixed seed. They match the
vendor format (so regex scanners detect them, keeping the baseline comparison
fair) but are not valid credentials.

The hard negatives are the point
--------------------------------
Regex scanners flag anything shaped like a key, so they drown in false
positives on `EXAMPLE_KEY = "AKIA..."`. Roughly half of our non-secrets are
deliberately format-valid-but-fake: docs examples, placeholders, redacted
values, test fixtures, environment-variable lookups. That is exactly where a
context-aware model should win, and it is what the objective's false-positive
analysis needs.

    python src/secrets_build.py --n 300
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C


def _alnum(rng: random.Random, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------- generators
# Each entry: (category, key-name hints, real-value generator)
SECRET_TYPES = [
    ("aws_access_key_id", "Authentication Key and Token", ["AWS_ACCESS_KEY_ID", "aws_key", "accessKeyId"],
     lambda r: "AKIA" + _alnum(r, 16, string.ascii_uppercase + string.digits)),
    ("aws_secret_access_key", "Authentication Key and Token", ["AWS_SECRET_ACCESS_KEY", "aws_secret"],
     lambda r: _alnum(r, 40, string.ascii_letters + string.digits + "/+")),
    ("github_pat", "Authentication Key and Token", ["GITHUB_TOKEN", "gh_token", "githubPat"],
     lambda r: "ghp_" + _alnum(r, 36)),
    ("slack_token", "Authentication Key and Token", ["SLACK_TOKEN", "slack_bot_token"],
     lambda r: f"xoxb-{_alnum(r,11,string.digits)}-{_alnum(r,12,string.digits)}-{_alnum(r,24)}"),
    ("stripe_secret", "API Key and Secret", ["STRIPE_SECRET_KEY", "stripe_key"],
     lambda r: "sk_live_" + _alnum(r, 24)),
    ("google_api_key", "API Key and Secret", ["GOOGLE_API_KEY", "gmaps_key"],
     lambda r: "AIza" + _alnum(r, 35, string.ascii_letters + string.digits + "_-")),
    ("twilio_key", "API Key and Secret", ["TWILIO_API_KEY", "twilio_sid"],
     lambda r: "SK" + _alnum(r, 32, "0123456789abcdef")),
    ("private_key", "Private Key", ["PRIVATE_KEY", "rsa_key"],
     lambda r: "-----BEGIN RSA PRIVATE KEY-----\\n" + _alnum(r, 64, string.ascii_letters + string.digits + "+/") + "\\n-----END RSA PRIVATE KEY-----"),
    ("db_url", "Database and Server URL", ["DATABASE_URL", "db_conn"],
     lambda r: f"postgres://admin:{_alnum(r,16)}@db.internal.example.com:5432/prod"),
    ("jwt", "Authentication Key and Token", ["JWT_SECRET", "auth_token"],
     lambda r: "eyJhbGciOiJIUzI1NiJ9." + _alnum(r, 40) + "." + _alnum(r, 43, string.ascii_letters + string.digits + "_-")),
    ("generic_password", "Generic Secret", ["DB_PASSWORD", "admin_password", "smtp_pass"],
     lambda r: _alnum(r, 18, string.ascii_letters + string.digits + "!@#$%")),
]

# Non-secrets that a regex scanner will still match, or nearly match.
FAKE_KINDS = [
    ("docs_example",    lambda r, t: {"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                                      "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                      "stripe_secret": "sk_live_XXXXXXXXXXXXXXXXXXXXXXXX",
                                      "google_api_key": "AIzaSyDOCS-EXAMPLE-KEY-NOT-REAL-000000",
                                      }.get(t, "EXAMPLE_VALUE_NOT_REAL")),
    ("placeholder",     lambda r, t: r.choice(["<YOUR_API_KEY_HERE>", "your-key-goes-here",
                                               "CHANGEME", "TODO_REPLACE_ME", "<insert key>"])),
    ("redacted",        lambda r, t: r.choice(["****************", "sk_live_****REDACTED****",
                                               "xxxxxxxxxxxxxxxxxxxx", "[REDACTED]"])),
    ("test_fixture",    lambda r, t: r.choice(["test-key-0000000000000000", "dummy_secret_value",
                                               "fake-token-for-unit-tests", "0" * 32])),
    ("env_reference",   lambda r, t: None),   # rendered as a lookup, not a literal
]

FILE_TEMPLATES = {
    "python": (".py", '{name} = "{value}"', "os.environ[\"{envname}\"]"),
    "javascript": (".js", 'const {name} = "{value}";', "process.env.{envname}"),
    "java": (".java", '    private static final String {name} = "{value}";', "System.getenv(\"{envname}\")"),
    "yaml": (".yml", "  {name}: \"{value}\"", "${{{envname}}}"),
    "env": (".env", "{name}={value}", "${{{envname}}}"),
    "properties": (".properties", "{name}={value}", "${{{envname}}}"),
    "json": (".json", '  "{name}": "{value}",', '"${{{envname}}}"'),
}

CONTEXT_HEADERS = {
    "production_config": "# Application configuration",
    "test_file": "# Unit test fixtures - values are not real credentials",
    "documentation": "# Example configuration from the README",
    "source": "# Service client setup",
}


def make_file(rng: random.Random, idx: int) -> dict:
    lang = rng.choice(list(FILE_TEMPLATES))
    ext, literal_tpl, env_tpl = FILE_TEMPLATES[lang]
    context = rng.choice(list(CONTEXT_HEADERS))
    # documentation and test files legitimately carry fake values
    real_bias = {"production_config": 0.55, "source": 0.5,
                 "test_file": 0.15, "documentation": 0.1}[context]

    n_entries = rng.randint(4, 9)
    lines = [CONTEXT_HEADERS[context], ""]
    findings = []

    for _ in range(n_entries):
        tname, category, hints, gen = rng.choice(SECRET_TYPES)
        key = rng.choice(hints)
        is_real = rng.random() < real_bias

        if is_real:
            value = gen(rng)
            line = literal_tpl.format(name=key, value=value)
            kind = "real_secret"
        else:
            kind, fake = rng.choice(FAKE_KINDS)
            if kind == "env_reference":
                line = literal_tpl.split("=")[0].rstrip() + " = " + env_tpl.format(envname=key.upper()) \
                    if lang in ("python", "javascript", "java") else f"{key}={env_tpl.format(envname=key.upper())}"
                value = None
            else:
                value = fake(rng, tname)
                line = literal_tpl.format(name=key, value=value)

        lines.append(line)
        findings.append({
            "line_no": len(lines),          # 1-based
            "key_name": key,
            "secret_type": tname,
            "category": category,
            "value": value,
            "is_real_secret": is_real,
            "non_secret_kind": None if is_real else kind,
            "line": line.strip(),
        })
        if rng.random() < 0.35:             # ordinary filler so files look natural
            lines.append(rng.choice([
                "TIMEOUT = 30", "DEBUG = False", "MAX_RETRIES = 5",
                "# see docs for details", "REGION = \"eu-west-1\"", "",
            ]))

    content = "\n".join(lines) + "\n"
    return {
        "file_id": hashlib.md5(f"secrets|{idx}".encode()).hexdigest()[:16],
        "filename": f"{'test_' if context=='test_file' else ''}config_{idx}{ext}",
        "language": lang,
        "context": context,
        "content": content,
        "n_entries": len(findings),
        "n_real_secrets": sum(1 for f in findings if f["is_real_secret"]),
        "findings": findings,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(C.PROCESSED / "secrets_benchmark.jsonl"))
    args = ap.parse_args()

    rng = random.Random(args.seed)
    files = [make_file(rng, i + 1) for i in range(args.n)]

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        for f in files:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    ent = [f for fl in files for f in fl["findings"]]
    real = [e for e in ent if e["is_real_secret"]]
    fake = [e for e in ent if not e["is_real_secret"]]
    print(f"files                : {len(files)}")
    print(f"  by language        : {dict(Counter(f['language'] for f in files))}")
    print(f"  by context         : {dict(Counter(f['context'] for f in files))}")
    print(f"entries              : {len(ent)}")
    print(f"  real secrets       : {len(real)}")
    print(f"  non-secrets        : {len(fake)}")
    print(f"  non-secret kinds   : {dict(Counter(e['non_secret_kind'] for e in fake))}")
    print(f"  secret types       : {len({e['secret_type'] for e in ent})}")
    print(f"  categories         : {dict(Counter(e['category'] for e in real))}")
    print(f"\nWrote -> {out}")
    print("\nNOTE: all values are randomly generated and non-functional. Format is")
    print("vendor-accurate so regex scanners detect them, keeping the baseline fair.")


if __name__ == "__main__":
    main()
