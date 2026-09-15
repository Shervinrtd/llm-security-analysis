"""Free-tier LLM providers behind one interface.

The scope note fixes the constraint: **no paid API calls**. Each provider below
has a genuinely free tier, but they differ in rate limit and daily quota, which
is what actually bounds how large an experiment we can run - so every call is
cached on disk and every provider declares its own spacing.

Set only the keys you have; `available()` reports which providers are live.

    GEMINI_API_KEY      https://aistudio.google.com/apikey        (generous free tier)
    GROQ_API_KEY        https://console.groq.com/keys             (free, very fast)
    OPENROUTER_API_KEY  https://openrouter.ai/keys                (has :free models)
    HF_TOKEN            https://huggingface.co/settings/tokens    (free inference)
    MISTRAL_API_KEY     https://console.mistral.ai/               (free tier)
    DEEPSEEK_API_KEY    https://platform.deepseek.com/            (paid, very cheap)

`StubProvider` needs no key and returns deterministic canned answers, so the
whole harness can be developed and tested offline.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

RESP_CACHE = C.CACHE / "responses"
RESP_CACHE.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- local models
# Ollama runs models on this machine. No API key, no rate limit, works offline.
OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
_OLLAMA_STATE: dict = {}


def _ollama_up(timeout: float = 1.5) -> bool:
    """Is a local Ollama server reachable? Cached, so it is cheap to call."""
    import socket
    if "up" in _OLLAMA_STATE:
        return _OLLAMA_STATE["up"]
    host = OLLAMA_URL.split("//")[-1].split("/")[0]
    h, _, p = host.partition(":")
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((h or "127.0.0.1", int(p or 11434)))
        _OLLAMA_STATE["up"] = True
    except Exception:
        _OLLAMA_STATE["up"] = False
    finally:
        s.close()
    return _OLLAMA_STATE["up"]


def _models_on_disk() -> list[str]:
    """Downloaded models read straight from Ollama's manifest folder.

    This deliberately does NOT need the server: it lets the app list local
    models (and let you tick them) while Ollama is still switched off. The
    server is only started when a model is actually used.
    Layout: ~/.ollama/models/manifests/<registry>/<namespace>/<model>/<tag>
    """
    root = Path(os.environ.get("OLLAMA_MODELS",
                               Path.home() / ".ollama" / "models")) / "manifests"
    if not root.exists():
        return []
    out = []
    for tag in root.rglob("*"):
        if tag.is_file():
            out.append(f"{tag.parent.name}:{tag.name}")
    return sorted(set(out))


def ollama_models() -> list[str]:
    """Which models are downloaded. Uses the server if it is up, else the disk."""
    if _ollama_up():
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            names = [m["name"] for m in r.json().get("models", [])]
            if names:
                return names
        except Exception:
            pass
    return _models_on_disk()


def ensure_ollama_running(timeout: float = 40.0, on_line=None) -> bool:
    """Start the local model server on demand, if it is not already up.

    Ollama normally installs a tray app that launches at every Windows login and
    sits in the background checking for updates. That autostart is disabled in
    this project; instead the server is started here only when a local model is
    actually needed, and it can be stopped again afterwards. We launch
    `ollama serve` (the bare server) rather than the tray app, so no update
    checker and no tray icon are involved.
    """
    import subprocess
    import time as _t

    _OLLAMA_STATE.pop("up", None)
    if _ollama_up():
        return True

    exe = find_ollama()
    if not exe:
        if on_line:
            on_line("Ollama is not installed (winget install Ollama.Ollama)")
        return False

    if on_line:
        on_line("starting local model server ...")
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":                       # no console window popping up
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.Popen([exe, "serve"], **kwargs)
        _OLLAMA_STATE["proc"] = proc
    except Exception as e:
        if on_line:
            on_line(f"could not start Ollama: {e}")
        return False

    deadline = _t.time() + timeout
    while _t.time() < deadline:
        _OLLAMA_STATE.pop("up", None)
        if _ollama_up():
            if on_line:
                on_line("local model server ready")
            return True
        _t.sleep(1.0)
    if on_line:
        on_line("local model server did not come up in time")
    return False


def stop_ollama(force: bool = False) -> bool:
    """Stop the local model server.

    By default only a server THIS process started is stopped. With force=True
    any running Ollama server is stopped - used by the app's "stop now" button
    and on exit, since the whole point of disabling Ollama's autostart is that
    it should not linger once you are done.
    """
    import subprocess
    stopped = False

    proc = _OLLAMA_STATE.pop("proc", None)
    _OLLAMA_STATE.pop("up", None)
    if proc is not None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
            stopped = True
        except Exception:
            pass

    if force and not stopped:
        try:
            if os.name == "nt":
                r = subprocess.run(["taskkill", "/F", "/IM", "ollama.exe"],
                                   capture_output=True, text=True)
                stopped = r.returncode == 0
            else:
                r = subprocess.run(["pkill", "-f", "ollama serve"], capture_output=True)
                stopped = r.returncode == 0
        except Exception:
            pass

    _OLLAMA_STATE.pop("up", None)
    return stopped


def find_ollama() -> str | None:
    """Locate the ollama executable (it is not always on PATH on Windows)."""
    import shutil as _sh
    exe = _sh.which("ollama")
    if exe:
        return exe
    for cand in (
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe",
        Path("C:/Program Files/Ollama/ollama.exe"),
        Path("/usr/local/bin/ollama"), Path("/usr/bin/ollama"),
    ):
        if cand.exists():
            return str(cand)
    return None


def ollama_pull(model: str, on_line=None) -> bool:
    """Download a local model. `on_line` receives progress lines."""
    exe = find_ollama()
    if not exe:
        if on_line:
            on_line("Ollama is not installed. Install it with:  winget install Ollama.Ollama")
        return False
    import subprocess
    try:
        proc = subprocess.Popen([exe, "pull", model], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", bufsize=1)
    except Exception as e:
        if on_line:
            on_line(f"could not start download: {e}")
        return False
    last = ""
    for line in proc.stdout:            # progress lines use \r; keep the newest
        line = line.replace("\r", "\n").strip().split("\n")[-1]
        if line and line != last and on_line:
            on_line(line[:110])
            last = line
    proc.wait()
    _OLLAMA_STATE.pop("models", None)
    return proc.returncode == 0


def set_api_key(env_var: str, value: str) -> None:
    """Persist an API key to the project's .env file and this process.

    The value is written to disk only - it is never logged or printed.
    """
    value = (value or "").strip()
    env_path = C.ROOT / ".env"
    lines = []
    if env_path.exists():
        lines = [l for l in env_path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if not l.strip().startswith(f"{env_var}=")]
    if value:
        lines.append(f"{env_var}={value}")
        os.environ[env_var] = value
    else:
        os.environ.pop(env_var, None)
    env_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def refresh() -> None:
    """Re-read .env and re-probe the local server, so availability is current."""
    # Keep ownership of a server this process started when refreshing probes.
    for key in tuple(_OLLAMA_STATE):
        if key != "proc":
            _OLLAMA_STATE.pop(key, None)
    _load_env_file()


def _load_env_file() -> None:
    """Load KEY=value lines from a `.env` file in the project root.

    This lets a user paste an API key into a simple text file instead of
    configuring OS environment variables (which is fiddly on Windows).
    Lines already present in the real environment are not overwritten.
    """
    env_path = C.ROOT / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if key and val and key not in os.environ:
            os.environ[key] = val


_load_env_file()


@dataclass
class Reply:
    text: str
    model: str
    ok: bool = True
    error: str = ""
    latency_s: float = 0.0
    cached: bool = False
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


@dataclass
class Provider:
    """One callable model endpoint."""
    name: str                 # short id used in results, e.g. "gemini-flash"
    model: str                # provider-side model id
    env_key: str              # environment variable holding the API key
    kind: str                 # openai_compatible | gemini | hf | stub
    base_url: str = ""
    min_interval_s: float = 4.0    # spacing to respect free-tier rate limits
    max_tokens: int = 700
    temperature: float = 0.0
    vendor: str = ""          # who MAKES the model (Meta, Google, OpenAI, ...),
                              # which is what the study compares - distinct from
                              # who HOSTS it (Groq, Ollama). The objective names
                              # OpenAI, Google and Meta specifically.
    _last_call: float = field(default=0.0, repr=False)

    # ---------------------------------------------------------------- helpers
    @property
    def api_key(self) -> str:
        return os.environ.get(self.env_key, "")

    def is_available(self) -> bool:
        if self.kind == "stub":
            return True
        if self.kind == "ollama":
            # Local models need no key at all. Availability depends only on the
            # weights being downloaded - NOT on the server already running,
            # because the server is started on demand at first use.
            have = ollama_models()
            if ":" in self.model:
                # a size tag is part of the identity: qwen2.5-coder:7b is NOT
                # satisfied by qwen2.5-coder:1.5b being present
                return self.model in have
            return any(m.split(":")[0] == self.model for m in have)
        return bool(self.api_key)

    def _throttle(self) -> None:
        wait = self.min_interval_s - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()

    def _cache_path(self, system: str, user: str) -> Path:
        key = hashlib.md5(
            f"{self.name}|{self.model}|{self.temperature}|{system}|{user}".encode()
        ).hexdigest()
        return RESP_CACHE / f"{key}.json"

    # ------------------------------------------------------------------ call
    def generate(self, system: str, user: str, use_cache: bool = True) -> Reply:
        cp = self._cache_path(system, user)
        if use_cache and cp.exists():
            try:
                d = json.loads(cp.read_text(encoding="utf-8"))
                return Reply(text=d["text"], model=self.model, ok=d.get("ok", True),
                             error=d.get("error", ""), latency_s=d.get("latency_s", 0.0),
                             cached=True)
            except Exception:
                pass

        self._throttle()
        t0 = time.time()
        try:
            if self.kind == "stub":
                reply = self._call_stub(system, user)
            elif self.kind == "ollama":
                reply = self._call_ollama(system, user)
            elif self.kind == "gemini":
                reply = self._call_gemini(system, user)
            elif self.kind == "hf":
                reply = self._call_hf(system, user)
            else:
                reply = self._call_openai_compatible(system, user)
        except Exception as e:                       # never crash a long sweep
            reply = Reply(text="", model=self.model, ok=False,
                          error=f"{type(e).__name__}: {e}")
        reply.latency_s = round(time.time() - t0, 2)

        if use_cache and reply.ok:
            cp.write_text(json.dumps({
                "text": reply.text, "ok": reply.ok, "error": reply.error,
                "latency_s": reply.latency_s}), encoding="utf-8")
        return reply

    # ------------------------------------------------------------- backends
    def _call_openai_compatible(self, system: str, user: str) -> Reply:
        r = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json",
                     "User-Agent": C.USER_AGENT},
            json={"model": self.model,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}],
                  "temperature": self.temperature,
                  "max_tokens": self.max_tokens},
            timeout=180,
        )
        if r.status_code != 200:
            return Reply("", self.model, ok=False,
                         error=f"HTTP {r.status_code}: {r.text[:200]}")
        d = r.json()
        usage = d.get("usage") or {}
        return Reply(
            text=d["choices"][0]["message"]["content"],
            model=self.model,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )

    def _call_gemini(self, system: str, user: str) -> Reply:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent")
        payload = {"systemInstruction": {"parts": [{"text": system}]},
                   "contents": [{"parts": [{"text": user}]}],
                   "generationConfig": {"temperature": self.temperature,
                                        "maxOutputTokens": self.max_tokens}}
        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

        # One polite retry on 429 (rate limit), honouring the server's retry hint.
        for attempt in range(2):
            r = requests.post(url, headers=headers, json=payload, timeout=180)
            if r.status_code == 429 and attempt == 0:
                delay = 20
                try:
                    for det in r.json().get("error", {}).get("details", []):
                        if "RetryInfo" in det.get("@type", ""):
                            delay = int(str(det.get("retryDelay", "20s")).rstrip("s")) + 2
                except Exception:
                    pass
                time.sleep(min(delay, 40))
                continue
            break

        if r.status_code != 200:
            hint = " (daily free quota exhausted - try again tomorrow or use another model)" \
                if r.status_code == 429 else ""
            return Reply("", self.model, ok=False,
                         error=f"HTTP {r.status_code}{hint}: {r.text[:160]}")
        d = r.json()
        try:
            parts = d["candidates"][0]["content"]["parts"]
            return Reply(text="".join(p.get("text", "") for p in parts), model=self.model)
        except (KeyError, IndexError):
            return Reply("", self.model, ok=False, error=f"unexpected shape: {str(d)[:200]}")

    def _call_ollama(self, system: str, user: str) -> Reply:
        """Local inference. No key, no quota - only limited by this machine.

        Starts the server on first use, so Ollama does not need to run in the
        background all the time.

        Resilient to sustained load. A long sweep of back-to-back requests can
        make the server drop connections or hand back an EMPTY response while the
        model is reloaded into GPU memory - which is what turned an earlier
        600-sample run into 80% unparseable answers. So: keep the model resident
        between calls (keep_alive), and retry transient failures and empty
        replies a few times with backoff before giving up. An empty reply is
        treated as a failure, never as a valid "nothing found" verdict.
        """
        if not _ollama_up() and not ensure_ollama_running():
            return Reply("", self.model, ok=False,
                         error="local model server could not be started "
                               "(is Ollama installed?)")
        last_err = ""
        for attempt in range(4):
            try:
                r = requests.post(
                    f"{OLLAMA_URL}/api/chat",
                    json={"model": self.model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}],
                          "stream": False,
                          "keep_alive": "10m",        # stay resident between calls
                          "options": {"temperature": self.temperature,
                                      "num_predict": self.max_tokens}},
                    timeout=600,      # local generation on a laptop GPU can be slow
                )
            except requests.RequestException as e:
                last_err = f"{type(e).__name__}: {e}"
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code == 404:
                return Reply("", self.model, ok=False,
                             error=f"HTTP 404 (model not downloaded - run:  "
                                   f"ollama pull {self.model})")
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}: {r.text[:160]}"
                time.sleep(1.5 * (attempt + 1))
                continue
            text = (r.json().get("message") or {}).get("content", "").strip()
            if text:
                return Reply(text=text, model=self.model)
            last_err = "empty response (server likely under load / reloading model)"
            time.sleep(1.5 * (attempt + 1))
        return Reply("", self.model, ok=False,
                     error=f"ollama failed after 4 attempts: {last_err}")

    def _call_hf(self, system: str, user: str) -> Reply:
        r = requests.post(
            f"https://api-inference.huggingface.co/models/{self.model}/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}],
                  "temperature": self.temperature, "max_tokens": self.max_tokens},
            timeout=180,
        )
        if r.status_code != 200:
            return Reply("", self.model, ok=False,
                         error=f"HTTP {r.status_code}: {r.text[:200]}")
        d = r.json()
        return Reply(text=d["choices"][0]["message"]["content"], model=self.model)

    def _call_stub(self, system: str, user: str) -> Reply:
        """Deterministic fake answers for offline harness testing.

        Keyed by prompt hash so the same input always yields the same reply, and
        it deliberately emits several *different* output formats to exercise the
        parser's fallback paths.
        """
        h = int(hashlib.md5(user.encode()).hexdigest(), 16)
        rng = random.Random(h)

        # Malware-triage task: emit that task's own verdict schema.
        if '"malicious"' in user:
            mal = rng.random() < 0.4
            tech = rng.choice(["exfiltration", "reverse-shell", "install-hook",
                               "obfuscated-exec", "download-executable"]) if mal else None
            return Reply(text=json.dumps({"malicious": mal, "technique": tech,
                                          "reason": "stub"}), model=self.model)

        # Secret-scanning task: name a random subset of the file's line numbers.
        if "real_secrets" in user:
            lines = [int(m) for m in re.findall(r"^(\d+):", user, re.M)]
            picked = [l for l in lines if rng.random() < 0.25]
            items = [{"line": l, "type": "credential", "reason": "literal value"} for l in picked]
            return Reply(text=json.dumps({"real_secrets": items}), model=self.model)

        # Dependency-review task: answer in that task's own schema, naming a
        # random subset of the packages actually present in the manifest.
        if "vulnerable_dependencies" in user:
            pkgs = re.findall(r'"([^"]+)"\s*:\s*"[\d][^"]*"', user)          # package.json
            pkgs += re.findall(r'^([A-Za-z0-9_.\-]+)==', user, re.M)          # requirements.txt
            pkgs += [f"{g}:{a}" for g, a in re.findall(
                r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", user)]
            pkgs = list(dict.fromkeys(pkgs))
            chosen = [p for p in pkgs if rng.random() < 0.3]
            items = [{"package": p, "version": "?", "reason": "known advisory"} for p in chosen]
            return Reply(text=json.dumps({"vulnerable_dependencies": items}), model=self.model)

        vulnerable = rng.random() < 0.45
        cwe = rng.choice(["CWE-787", "CWE-125", "CWE-79", "CWE-89", "CWE-476", "CWE-416"])
        style = h % 4
        if not vulnerable:
            body = ('{"vulnerable": false, "cwe": null, "reason": "No unsanitised path found."}'
                    if style else "After review, the function is not vulnerable.")
        elif style == 0:
            body = f'{{"vulnerable": true, "cwe": "{cwe}", "reason": "Unsanitised path to sink."}}'
        elif style == 1:
            body = f'Analysis...\n```json\n{{"vulnerable": true, "cwe": "{cwe}", "reason": "r"}}\n```'
        elif style == 2:
            body = f"vulnerability: **YES** | vulnerability type: **{cwe}**"
        else:
            body = f"The function is vulnerable. Type: {cwe.replace('-', '_')}."
        return Reply(text=body, model=self.model)


# --------------------------------------------------------------- registry
REGISTRY: dict[str, Provider] = {
    "stub": Provider("stub", "stub-v1", "", "stub", min_interval_s=0.0),

    # ---- LOCAL models: no API key, no rate limit, run on this machine ----
    # These are the same open models used by papers 3 and 4, so results here are
    # directly comparable with their published numbers.
    "local-qwen-coder": Provider(
        "local-qwen-coder", "qwen2.5-coder:7b", "", "ollama",
        min_interval_s=0.0, max_tokens=800, vendor="Alibaba"),
    "local-qwen-coder-small": Provider(
        "local-qwen-coder-small", "qwen2.5-coder:1.5b", "", "ollama",
        min_interval_s=0.0, max_tokens=800, vendor="Alibaba"),
    "local-llama": Provider(          # Meta, run locally
        "local-llama", "llama3.2:3b", "", "ollama",
        min_interval_s=0.0, max_tokens=800, vendor="Meta"),

    # The newest flagship Gemini (gemini-3.6-flash) allows only 20 free requests
    # per DAY - unusable for an experiment. The "lite" line has a far more
    # generous free daily quota and is a lighter (non-"thinking") model, so it
    # also avoids the answer-truncation issue. `-latest` auto-tracks the current
    # lite release.
    # ---- Google: the objective names it. Free daily quota on the lite line. ----
    "gemini-flash": Provider(
        "gemini-flash", "gemini-flash-lite-latest", "GEMINI_API_KEY", "gemini",
        min_interval_s=2.5, max_tokens=1024, vendor="Google"),

    # ---- Meta: the objective names it. Llama, hosted free & fast on Groq. ----
    "groq-llama": Provider(
        "groq-llama", "llama-3.3-70b-versatile", "GROQ_API_KEY", "openai_compatible",
        base_url="https://api.groq.com/openai/v1", min_interval_s=2.5, vendor="Meta"),
    # a smaller, higher-throughput Meta option on the same free Groq key
    "groq-llama-8b": Provider(
        "groq-llama-8b", "llama-3.1-8b-instant", "GROQ_API_KEY", "openai_compatible",
        base_url="https://api.groq.com/openai/v1", min_interval_s=2.0, vendor="Meta"),

    # ---- OpenAI: the third vendor the objective names. Needs a paid key, but
    #      the slot exists so the comparison can include it when one is provided.
    "openai-gpt": Provider(
        "openai-gpt", "gpt-4o-mini", "OPENAI_API_KEY", "openai_compatible",
        base_url="https://api.openai.com/v1", min_interval_s=1.0, vendor="OpenAI"),

    "openrouter-qwen": Provider(
        "openrouter-qwen", "qwen/qwen-2.5-coder-32b-instruct:free",
        "OPENROUTER_API_KEY", "openai_compatible",
        base_url="https://openrouter.ai/api/v1", min_interval_s=4.0, vendor="Alibaba"),

    "openrouter-deepseek": Provider(
        "openrouter-deepseek", "deepseek/deepseek-chat-v3-0324:free",
        "OPENROUTER_API_KEY", "openai_compatible",
        base_url="https://openrouter.ai/api/v1", min_interval_s=4.0, vendor="DeepSeek"),

    "mistral-small": Provider(
        "mistral-small", "mistral-small-latest", "MISTRAL_API_KEY", "openai_compatible",
        base_url="https://api.mistral.ai/v1", min_interval_s=2.0, vendor="Mistral"),

    "hf-starcoder2": Provider(
        "hf-starcoder2", "bigcode/starcoder2-15b-instruct-v0.1", "HF_TOKEN", "hf",
        min_interval_s=3.0, vendor="BigCode"),
}


def available() -> list[str]:
    return [n for n, p in REGISTRY.items() if p.is_available()]


def get(name: str) -> Provider:
    if name not in REGISTRY:
        raise KeyError(f"unknown provider '{name}'. known: {sorted(REGISTRY)}")
    return REGISTRY[name]


if __name__ == "__main__":
    print("provider           key env              available")
    print("-" * 56)
    for n, p in REGISTRY.items():
        print(f"{n:<19}{p.env_key or '(none)':<21}{'YES' if p.is_available() else 'no'}")
    print(f"\navailable now: {available()}")
    print("\nstub smoke test:")
    s = get("stub")
    for q in ["function A", "function B", "function C", "function D"]:
        r = s.generate("sys", q)
        print(f"  {q}: {r.text[:72]!r}")
