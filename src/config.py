"""Central configuration for the multi-language vulnerability dataset pipeline.

Scope is fixed by "Project Scope Note.docx": 4 languages, real-world CVE-linked
data, function-level multi-class (CWE) detection.
"""
from pathlib import Path

# ---------------------------------------------------------------- paths
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RAW = DATA / "raw"
INTERIM = DATA / "interim"
PROCESSED = DATA / "processed"
CACHE = DATA / "cache"
for _p in (RAW, INTERIM, PROCESSED, CACHE):
    _p.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- languages
# Locked in the scope note: Java, C/C++, Python, JavaScript.
# C and C++ are tracked separately internally but reported as one "c/cpp" family.
EXT_TO_LANG = {
    ".c": "c",
    ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
}
LANG_FAMILY = {
    "c": "c/cpp", "cpp": "c/cpp",
    "java": "java", "python": "python", "javascript": "javascript",
}
TARGET_LANGS = ["c", "cpp", "java", "python", "javascript"]

# tree-sitter node types that represent a callable definition, per language.
FUNC_NODE_TYPES = {
    "c":          {"function_definition"},
    "cpp":        {"function_definition"},
    "java":       {"method_declaration", "constructor_declaration"},
    "python":     {"function_definition"},
    "javascript": {"function_declaration", "method_definition",
                   "function_expression", "arrow_function",
                   "generator_function_declaration"},
}

# ---------------------------------------------------------------- NVD
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Public rate limit is 5 requests / 30s (no API key) -> 6s spacing, +margin.
NVD_SLEEP_NO_KEY = 6.5
NVD_SLEEP_WITH_KEY = 0.7
NVD_PAGE_SIZE = 2000  # API maximum

# ---------------------------------------------------------------- GitHub
# NOTE: we deliberately use github.com/<repo>/commit/<sha>.patch (a plain web
# endpoint) rather than api.github.com, which is capped at 60 req/hr when
# unauthenticated. The .patch route is what makes this pipeline scalable
# without requiring every user to hold a GitHub token.
GH_PATCH_URL = "https://github.com/{repo}/commit/{sha}.patch"
# Spacing between downloads. These are plain web/CDN endpoints rather than the
# rate-limited API, so 1s is polite while keeping a multi-thousand-CVE build to
# a few hours. Raise it if you start seeing HTTP 429s.
GH_SLEEP = 1.0
GH_MAX_PATCH_BYTES = 2_000_000   # skip mega-commits (usually refactors, not fixes)

USER_AGENT = "academic-vuln-dataset-builder/0.1 (defensive security research)"

# ---------------------------------------------------------------- filtering
# Per the scope note (Section 3, Step B) and SecVulEval's methodology.
MAX_FILES_PER_COMMIT = 8      # multi-file mega-commits are usually refactors
MIN_FUNC_LOC = 3              # discard trivial stubs
MAX_FUNC_LOC = 800            # discard pathological outliers
MAX_CHANGED_FUNCS_PER_COMMIT = 12
# Cap untouched "safe" functions taken from any single file. Without this, one
# large file can donate 100+ negatives and dominate the corpus.
MAX_UNCHANGED_PER_FILE = 5

# Commit-message markers that signal a non-security or tangled change.
NOISE_MARKERS = (
    "merge branch", "merge pull request", "revert ", "typo",
    "reformat", "re-format", "indentation", "whitespace",
    "bump version", "update changelog", "release notes",
)

__all__ = [
    "ROOT", "DATA", "RAW", "INTERIM", "PROCESSED", "CACHE",
    "EXT_TO_LANG", "LANG_FAMILY", "TARGET_LANGS", "FUNC_NODE_TYPES",
    "NVD_API", "NVD_SLEEP_NO_KEY", "NVD_SLEEP_WITH_KEY", "NVD_PAGE_SIZE",
    "GH_PATCH_URL", "GH_SLEEP", "GH_MAX_PATCH_BYTES", "USER_AGENT",
    "MAX_FILES_PER_COMMIT", "MIN_FUNC_LOC", "MAX_FUNC_LOC",
    "MAX_CHANGED_FUNCS_PER_COMMIT", "NOISE_MARKERS",
]
