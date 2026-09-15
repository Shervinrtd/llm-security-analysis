"""Step B - Fetch commit patches and reconstruct pre-/post-fix file contents.

Design note
-----------
We avoid api.github.com entirely (60 req/hr unauthenticated). Instead:

  * commit diff  <- https://github.com/<repo>/commit/<sha>.patch
  * post-fix file <- https://raw.githubusercontent.com/<repo>/<sha>/<path>
  * pre-fix file  <- reconstructed by REVERSE-APPLYING the diff hunks to the
                     post-fix file.

Reverse-applying is exact (a unified diff carries every removed line verbatim)
and saves one network fetch per file versus resolving the parent commit.
Everything is cached on disk, so re-runs are free.
"""
from __future__ import annotations

import hashlib
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config as C

PATCH_CACHE = C.CACHE / "patches"
FILE_CACHE = C.CACHE / "files"
PATCH_CACHE.mkdir(parents=True, exist_ok=True)
FILE_CACHE.mkdir(parents=True, exist_ok=True)

RAW_URL = "https://raw.githubusercontent.com/{repo}/{sha}/{path}"
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": C.USER_AGENT})


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)   # raw diff lines: ' ', '-', '+'


@dataclass
class FileDiff:
    path: str                    # post-fix path
    old_path: str
    is_new: bool = False
    is_deleted: bool = False
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def changed_new_lines(self) -> set[int]:
        """1-based line numbers ADDED/modified in the post-fix file."""
        out, ln = set(), 0
        for h in self.hunks:
            ln = h.new_start
            for raw in h.lines:
                if raw.startswith("+"):
                    out.add(ln); ln += 1
                elif raw.startswith("-"):
                    pass
                else:
                    ln += 1
        return out

    @property
    def changed_old_lines(self) -> set[int]:
        """1-based line numbers REMOVED/modified in the pre-fix file."""
        out, ln = set(), 0
        for h in self.hunks:
            ln = h.old_start
            for raw in h.lines:
                if raw.startswith("-"):
                    out.add(ln); ln += 1
                elif raw.startswith("+"):
                    pass
                else:
                    ln += 1
        return out


def _cache_key(*parts: str) -> str:
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def fetch_patch(repo: str, sha: str, timeout: int = 60) -> str | None:
    """Download a commit's unified diff. Returns None on failure/oversize."""
    key = _cache_key(repo, sha)
    cf = PATCH_CACHE / f"{key}.patch"
    if cf.exists():
        txt = cf.read_text(encoding="utf-8", errors="replace")
        return txt if txt else None

    url = C.GH_PATCH_URL.format(repo=repo, sha=sha)
    try:
        r = _SESSION.get(url, timeout=timeout)
    except requests.RequestException:
        return None
    time.sleep(C.GH_SLEEP)
    if r.status_code != 200:
        cf.write_text("", encoding="utf-8")     # negative-cache
        return None
    if len(r.content) > C.GH_MAX_PATCH_BYTES:
        cf.write_text("", encoding="utf-8")
        return None
    txt = r.text
    cf.write_text(txt, encoding="utf-8")
    return txt


def fetch_file(repo: str, sha: str, path: str, timeout: int = 60) -> str | None:
    """Download a single file at a given commit (post-fix content)."""
    key = _cache_key(repo, sha, path)
    cf = FILE_CACHE / f"{key}.txt"
    if cf.exists():
        txt = cf.read_text(encoding="utf-8", errors="replace")
        return txt if txt else None

    url = RAW_URL.format(repo=repo, sha=sha, path=path)
    try:
        r = _SESSION.get(url, timeout=timeout)
    except requests.RequestException:
        return None
    time.sleep(C.GH_SLEEP)
    if r.status_code != 200 or len(r.content) > C.GH_MAX_PATCH_BYTES:
        cf.write_text("", encoding="utf-8")
        return None
    txt = r.text
    cf.write_text(txt, encoding="utf-8")
    return txt


def parse_patch(patch_text: str) -> list[FileDiff]:
    """Parse a unified diff into per-file hunk structures."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    cur_hunk: Hunk | None = None

    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            cur = None
            cur_hunk = None
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            if m:
                cur = FileDiff(path=m.group(2), old_path=m.group(1))
                files.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            cur.is_new = True; continue
        if line.startswith("deleted file mode"):
            cur.is_deleted = True; continue
        if line.startswith("--- "):
            if line.strip() == "--- /dev/null":
                cur.is_new = True
            continue
        if line.startswith("+++ "):
            if line.strip() == "+++ /dev/null":
                cur.is_deleted = True
            continue
        m = HUNK_RE.match(line)
        if m:
            cur_hunk = Hunk(
                old_start=int(m.group(1)), old_count=int(m.group(2) or 1),
                new_start=int(m.group(3)), new_count=int(m.group(4) or 1),
            )
            cur.hunks.append(cur_hunk)
            continue
        if cur_hunk is not None and line[:1] in (" ", "+", "-", ""):
            if line.startswith("\\"):      # "\ No newline at end of file"
                continue
            cur_hunk.lines.append(line if line else " ")
    return files


def reverse_apply(post_text: str, fd: FileDiff) -> str | None:
    """Reconstruct the PRE-fix file by reverse-applying hunks to the post-fix file.

    Returns None if the diff does not line up with the fetched file (e.g. the
    file moved, or the patch is truncated) - callers should skip such samples
    rather than trust a bad reconstruction.
    """
    post = post_text.splitlines()
    out: list[str] = []
    cursor = 0     # 0-based index into post

    for h in sorted(fd.hunks, key=lambda x: x.new_start):
        start = h.new_start - 1
        if start < cursor or start > len(post):
            return None
        out.extend(post[cursor:start])

        old_lines, consumed = [], 0
        for raw in h.lines:
            tag, content = raw[:1], raw[1:]
            if tag == " ":
                old_lines.append(content); consumed += 1
            elif tag == "-":
                old_lines.append(content)
            elif tag == "+":
                consumed += 1

        # Verify the hunk's context/added lines actually match the fetched file.
        expect = [raw[1:] for raw in h.lines if raw[:1] in (" ", "+")]
        actual = post[start:start + consumed]
        if expect != actual:
            return None

        out.extend(old_lines)
        cursor = start + consumed

    out.extend(post[cursor:])
    return "\n".join(out)


def lang_of(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    return C.EXT_TO_LANG.get(ext)


def is_noisy_commit(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in C.NOISE_MARKERS)


def commit_message_from_patch(patch_text: str) -> str:
    """Extract the commit subject/body that git format-patch embeds."""
    lines, subject, body = patch_text.splitlines(), "", []
    for i, ln in enumerate(lines):
        if ln.startswith("Subject: "):
            subject = re.sub(r"^Subject:\s*(\[PATCH[^\]]*\]\s*)?", "", ln).strip()
            for nxt in lines[i + 1:]:
                if nxt.startswith("diff --git ") or nxt.startswith("---"):
                    break
                body.append(nxt)
            break
    return (subject + "\n" + "\n".join(body)).strip()


__all__ = ["Hunk", "FileDiff", "fetch_patch", "fetch_file", "parse_patch",
           "reverse_apply", "lang_of", "is_noisy_commit", "commit_message_from_patch"]
