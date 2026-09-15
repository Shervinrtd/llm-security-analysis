"""Read a dependency manifest into (package, version) pairs.

Needed for two things:

  1. the dependency prompt can list the actual dependencies instead of dumping
     raw file text at the model, and
  2. a (package, version) pair is what an advisory database is keyed on, so
     without it no CVE can be attached to a finding.

Package names follow the ecosystem's own convention, because that is what the
advisory data uses:

    PyPI    flask                       (lower-cased, - and _ normalised)
    npm     express, @scope/name
    Maven   groupId:artifactId

A version of None means "declared, but not pinned to one version" (a range, a
wildcard, or a property reference). Those are reported but cannot be matched
exactly against an advisory.
"""
from __future__ import annotations

import json
import re
from xml.etree import ElementTree

# ---------------------------------------------------------------------------
MANIFEST_ECOSYSTEM = {
    "requirements.txt": "PyPI", "requirements-dev.txt": "PyPI", "pipfile": "PyPI",
    "pyproject.toml": "PyPI", "setup.py": "PyPI",
    "package.json": "npm", "package-lock.json": "npm",
    "pom.xml": "Maven", "build.gradle": "Maven", "build.gradle.kts": "Maven",
}

# strip an npm/pip range operator off the front of a version string
_RANGE_PREFIX = re.compile(r"^[\^~>=<!\s]*")
# a bare, fully-pinned version: 1, 1.2, 1.2.3, 1.2.3-rc1, 1.2.3.post1
_EXACT = re.compile(r"^\d+(?:\.\w+)*(?:[-+.]\w+)*$")


def normalise(ecosystem: str, name: str) -> str:
    """Canonical package name for the ecosystem's advisory data."""
    name = name.strip()
    if ecosystem == "PyPI":
        # PEP 503: names are case-insensitive and -/_/. are equivalent
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name          # Maven coordinates are case-sensitive


def _clean_version(raw: str | None) -> str | None:
    """Return an exactly-pinned version, or None for ranges/wildcards/vars."""
    if not raw:
        return None
    v = _RANGE_PREFIX.sub("", str(raw).strip().strip('"\''))
    v = v.split(",")[0].strip()
    if not v or v in ("*", "latest", "x") or v.startswith("$"):
        return None
    return v if _EXACT.match(v) else None


# ------------------------------------------------------------- per-format
def _requirements(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue                       # -r includes, -e editables, flags
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        ver = None
        pin = re.match(r"^===?\s*([^\s;,]+)", rest)
        if pin:
            ver = _clean_version(pin.group(1))
        out.append({"package": name, "version": ver})
    return out


def _package_json(text: str) -> list[dict]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (obj.get(section) or {}).items():
            out.append({"package": name, "version": _clean_version(spec)})
    return out


def _package_lock(text: str) -> list[dict]:
    """Lockfiles pin exactly, so they are the most useful input we can get."""
    try:
        obj = json.loads(text)
    except Exception:
        return []
    out = []
    # npm v7+ layout
    for path, meta in (obj.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue                       # "" is the root project itself
        name = meta.get("name") or path.split("node_modules/")[-1]
        if meta.get("version"):
            out.append({"package": name, "version": _clean_version(meta["version"])})
    # npm v6 layout
    for name, meta in (obj.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            out.append({"package": name, "version": _clean_version(meta["version"])})
    return out


def _pom(text: str) -> list[dict]:
    try:
        root = ElementTree.fromstring(text)
    except Exception:
        return []
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[: root.tag.index("}") + 1]
    out = []
    for dep in root.iter(f"{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId")
        aid = dep.findtext(f"{ns}artifactId")
        ver = dep.findtext(f"{ns}version")
        if gid and aid:
            out.append({"package": f"{gid.strip()}:{aid.strip()}",
                        "version": _clean_version(ver)})
    return out


_GRADLE = re.compile(
    r"""(?:implementation|api|compile|testImplementation|runtimeOnly|classpath)\s*"""
    r"""\(?\s*['"]([^'"\s:]+):([^'"\s:]+)(?::([^'"\s]+))?['"]""")


def _gradle(text: str) -> list[dict]:
    return [{"package": f"{g}:{a}", "version": _clean_version(v)}
            for g, a, v in _GRADLE.findall(text)]


_PARSERS = {
    "requirements.txt": _requirements, "requirements-dev.txt": _requirements,
    "pipfile": _requirements,
    "package.json": _package_json, "package-lock.json": _package_lock,
    "pom.xml": _pom, "build.gradle": _gradle, "build.gradle.kts": _gradle,
}


# ---------------------------------------------------------------- public
def parse(filename: str, content: str) -> tuple[str, list[dict]]:
    """(ecosystem, [{package, version, raw_name}, ...]) for a manifest file."""
    key = filename.lower()
    eco = MANIFEST_ECOSYSTEM.get(key, "PyPI")
    parser = _PARSERS.get(key)
    if parser is None:
        return eco, []
    seen, out = set(), []
    for d in parser(content):
        raw = d["package"]
        norm = normalise(eco, raw)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append({"package": norm, "raw_name": raw, "version": d["version"]})
    return eco, out


if __name__ == "__main__":       # tiny self-check
    demo = {
        "requirements.txt": "Flask==1.0\nrequests>=2.0\n# note\nDjango===3.1.1\n",
        "package.json": '{"dependencies":{"express":"^4.17.1","lodash":"4.17.20"}}',
        "pom.xml": "<project><dependencies><dependency><groupId>org.apache.spark"
                   "</groupId><artifactId>spark-core_2.12</artifactId>"
                   "<version>3.0.0</version></dependency></dependencies></project>",
        "build.gradle": "implementation 'com.google.guava:guava:30.0-jre'\n",
    }
    for fn, txt in demo.items():
        eco, deps = parse(fn, txt)
        print(f"{fn:<20} [{eco}] {deps}")
