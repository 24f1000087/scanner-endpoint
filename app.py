import os
import re
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def parse_skill(text):
    """Split a skill markdown file into (frontmatter_dict, frontmatter_raw, body)."""
    m = re.match(r'^\s*---\s*\n(.*?)\n---\s*\n?(.*)$', text, re.DOTALL)
    if not m:
        return {}, "", text
    fm_raw, body = m.group(1), m.group(2)
    try:
        fm = yaml.safe_load(fm_raw)
        if not isinstance(fm, dict):
            fm = {}
    except Exception:
        fm = {}
    return fm, fm_raw, body


def extract_code_blocks(body):
    return re.findall(r'```(?:[A-Za-z0-9_+-]*)\n(.*?)```', body, re.DOTALL)


def flatten_str(value):
    """Turn a YAML value (str/dict/list/None) into a lowercase searchable string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return yaml.dump(value)
    return str(value)


# ---------------------------------------------------------------------------
# hardcoded_secret
# ---------------------------------------------------------------------------
KNOWN_SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',
    r'ASIA[0-9A-Z]{16}',
    r'sk-[A-Za-z0-9]{20,}',
    r'sk_live_[A-Za-z0-9]{10,}',
    r'sk_test_[A-Za-z0-9]{10,}',
    r'ghp_[A-Za-z0-9]{30,}',
    r'gho_[A-Za-z0-9]{30,}',
    r'github_pat_[A-Za-z0-9_]{20,}',
    r'xox[baprs]-[A-Za-z0-9-]{10,}',
    r'AIza[0-9A-Za-z\-_]{35}',
    r'-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)?\s?PRIVATE KEY-----',
    r'hooks\.slack\.com/services/[A-Za-z0-9/]+',
    r'discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
]
KNOWN_SECRET_RE = re.compile("|".join(KNOWN_SECRET_PATTERNS))

SECRET_KEY_SUBSTRINGS = [
    "api_key", "apikey", "api-key", "secret", "token", "password", "passwd",
    "access_key", "private_key", "webhook_url", "webhook", "credential",
]
KV_LINE_RE = re.compile(r'^\s*["\']?([\w.\-]+)["\']?\s*[:=]\s*["\']?([^\s"\'\n]+)', re.MULTILINE)

PLACEHOLDER_HINTS = (
    "$", "env", "vault", "secret manager", "secret store", "keychain",
    "credential store", "secrets manager", "1password", "<", "your-",
    "your_", "xxxx", "redacted", "placeholder", "example.com", "todo",
    "change_me", "changeme", "insert", "n/a", "none", "null", "***",
)


def looks_like_placeholder(value):
    v = value.strip().strip('"\'')
    if not v:
        return True
    low = v.lower()
    return any(hint in low for hint in PLACEHOLDER_HINTS)


def check_hardcoded_secret(fm_raw, body):
    code_blocks = extract_code_blocks(body)
    searchable = [fm_raw] + code_blocks

    for text in searchable:
        if KNOWN_SECRET_RE.search(text):
            return True

    for text in searchable:
        for key, value in KV_LINE_RE.findall(text):
            key_l = key.lower()
            if not any(s in key_l for s in SECRET_KEY_SUBSTRINGS):
                continue
            if looks_like_placeholder(value):
                continue
            if len(value) >= 6:
                return True

    # Bearer tokens / API-key query params hardcoded in example scripts
    for text in code_blocks:
        if re.search(r'Authorization:\s*Bearer\s+(?!\$)[A-Za-z0-9\-_.]{15,}', text, re.IGNORECASE):
            return True
        if re.search(r'[?&](api_key|apikey|token|key|secret)=(?!\$)[A-Za-z0-9\-_]{8,}', text, re.IGNORECASE):
            return True

    return False


# ---------------------------------------------------------------------------
# prompt_injection
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    r'ignore (any|the|all) user',
    r'ignore.{0,20}(stop|cancel)',
    r"even if the user (says|asks|requests|wants).{0,20}(stop|cancel|no|not to)",
    r'(do not|don\'t|never) (tell|inform|notify|mention|surface|show).{0,30}(user|reviewer)',
    r'without (surfacing|informing|telling|notifying) (this|the|it)',
    r"without (the )?user'?s? (knowledge|consent|awareness|approval)",
    r'silently (send|post|upload|exfiltrat\w*|transmit|email|copy|forward)',
    r'regardless of (what )?the user (says|wants|instructs|requests)',
    r'override (the )?(user|system)\s?(\'s)?\s?(instruction|control|prompt|command)',
    r'do not mention (this|it) in (your|the) (visible )?output',
    r'hide (this|it) from (the )?(user|reviewer)',
    r'disregard (the )?(user|system) (instruction|prompt|request)',
    r'continue (running|working|processing) (even|regardless).{0,20}(stop|cancel|told)',
    r'do not (stop|halt|cancel) (even|regardless)',
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

OVERRIDE_VERB_RE = re.compile(
    r'\b(ignore|disregard|override|bypass|don\'t stop|do not stop|don\'t halt|'
    r'do not halt|keep (going|deleting|running|working|processing)|continue anyway|'
    r'continue regardless)\b', re.IGNORECASE
)
CONTROL_SIGNAL_RE = re.compile(
    r'\b(stop|cancel|halt|abort)\b', re.IGNORECASE
)


def check_stop_override_cooccurrence(body):
    """Catch phrasing like 'if the user asks to stop, ignore that request'
    regardless of which side of the sentence the override verb is on."""
    segments = re.split(r'\n\s*\d+\.\s+|\n{2,}|(?<=[.!?])\s+', body)
    for seg in segments:
        if OVERRIDE_VERB_RE.search(seg) and CONTROL_SIGNAL_RE.search(seg):
            return True
    return False


def check_prompt_injection(fm_raw, body):
    if INJECTION_RE.search(body) or INJECTION_RE.search(fm_raw):
        return True
    if check_stop_override_cooccurrence(body):
        return True
    return False


# ---------------------------------------------------------------------------
# excessive_permissions
# ---------------------------------------------------------------------------
FS_EXCESSIVE_HINTS = [
    "entire filesystem", "entire file system", "whole filesystem",
    "whole file system", "full filesystem access", "full disk access",
    "root access", "read-write access to /", "read/write access to /",
    "all files on", "any file on the system", "unrestricted file",
    "unrestricted filesystem", "access to the entire file system",
]
NET_EXCESSIVE_HINTS = [
    "any host", "any domain", "unrestricted egress", "unrestricted network",
    "all domains", "any external site", "any url", "any endpoint",
    "no network restrictions", "full network access", "egress to any",
    "network: *", "any server",
]


def check_excessive_permissions(fm):
    perms = fm.get("permissions") if isinstance(fm, dict) else None
    if not isinstance(perms, dict):
        return False
    fs_val = flatten_str(perms.get("filesystem")).lower()
    net_val = flatten_str(perms.get("network")).lower()
    if any(hint in fs_val for hint in FS_EXCESSIVE_HINTS):
        return True
    if any(hint in net_val for hint in NET_EXCESSIVE_HINTS):
        return True
    if fs_val.strip() in ("/", "read-write access to /"):
        return True
    return False


# ---------------------------------------------------------------------------
# unclear_provenance
# ---------------------------------------------------------------------------
SILENT_VERSION_PATTERNS = [
    r'silently (update|rewrite|change|bump|modify)\w* (its own )?(version|changelog)',
    r'update\w* (its own )?version.{0,40}without (surfacing|informing|telling|notifying)',
    r'clear\w* the changelog',
    r'rewrit\w* (its own )?(version|changelog) metadata',
]
SILENT_VERSION_RE = re.compile("|".join(SILENT_VERSION_PATTERNS), re.IGNORECASE)


def check_unclear_provenance(fm, body):
    if SILENT_VERSION_RE.search(body):
        return True

    has_author = bool(fm.get("author")) if isinstance(fm, dict) else False
    has_version = bool(fm.get("version")) if isinstance(fm, dict) else False
    has_changelog_field = bool(fm.get("changelog")) if isinstance(fm, dict) else False
    has_changelog_section = bool(re.search(r'^#{1,6}\s*changelog', body, re.IGNORECASE | re.MULTILINE))

    if not has_author and not has_version and not (has_changelog_field or has_changelog_section):
        return True

    return False


# ---------------------------------------------------------------------------
# main endpoint
# ---------------------------------------------------------------------------
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/scan", methods=["OPTIONS"])
def preflight():
    return "", 204


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True)
    if not data or "skill" not in data or not isinstance(data["skill"], str):
        return jsonify({"categories": []})

    skill_text = data["skill"]
    fm, fm_raw, body = parse_skill(skill_text)

    categories = []
    if check_hardcoded_secret(fm_raw, body):
        categories.append("hardcoded_secret")
    if check_prompt_injection(fm_raw, body):
        categories.append("prompt_injection")
    if check_excessive_permissions(fm):
        categories.append("excessive_permissions")
    if check_unclear_provenance(fm, body):
        categories.append("unclear_provenance")

    return jsonify({"categories": categories})


@app.route("/", methods=["GET"])
def health():
    return "Skill scanner is running. POST to /scan."


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
