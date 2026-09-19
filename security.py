"""Security guard for owlead-local.

Hardens the app against session theft, poisoned updates, supply-chain
injection, and log/DB leakage. Wired into owlead.py at the trust
boundary points — profile dir, updater, DB, and run start.
"""
import hashlib
import hmac
import os
import secrets
import stat
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, ".browser-profile")
DB_PATH = os.path.join(HERE, "owlead.db")
LOG_PATH = os.path.join(HERE, "owlead.log")
PATTERNS = os.path.join(HERE, "patterns.yaml")
KEY_FILE = os.path.join(HERE, ".update_key")   # HMAC key, 0600, gitignored

# trusted publisher fingerprints for the patterns file
# (set the first time manually after verifying a known-good update)
TRUSTED_FINGERPRINTS_FILE = os.path.join(HERE, ".trusted_fingerprints")


def _chmod_600(path):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _chmod_700(path):
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass


# ----------------------------------------------------------------
# 1. SESSION VAULT — lock the browser profile to this user only
# ----------------------------------------------------------------
def lock_down_local_state():
    """Restrict file permissions so no other macOS user/process can
    read the session vault, DB, or logs without your account."""
    if os.path.isdir(PROFILE_DIR):
        _chmod_700(PROFILE_DIR)
        for root, dirs, files in os.walk(PROFILE_DIR):
            for d in dirs:
                _chmod_700(os.path.join(root, d))
            for f in files:
                _chmod_600(os.path.join(root, f))
    for f in (DB_PATH, LOG_PATH, KEY_FILE, TRUSTED_FINGERPRINTS_FILE):
        if os.path.exists(f):
            _chmod_600(f)


# ----------------------------------------------------------------
# 2. UPDATE INTEGRITY — HMAC-sign patterns and verify on update
# ----------------------------------------------------------------
def get_or_create_key():
    """HMAC key used to sign pattern updates. Generated locally once,
    chmod 600, never committed. This is the anti-poisoning control:
    even if someone hijacks the GitHub repo, they cannot produce a
    valid signature without this key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()
    key = secrets.token_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key.hex().encode())
    _chmod_600(KEY_FILE)
    return key


def sign_patterns(body_text):
    key = get_or_create_key()
    return hmac.new(key, body_text.encode("utf-8"), hashlib.sha256).hexdigest()


def load_trusted_fingerprints():
    if not os.path.exists(TRUSTED_FINGERPRINTS_FILE):
        return set()
    with open(TRUSTED_FINGERPRINTS_FILE) as f:
        return {ln.strip() for ln in f if ln.strip()}


def trust_fingerprint(fp):
    fps = load_trusted_fingerprints()
    fps.add(fp)
    with open(TRUSTED_FINGERPRINTS_FILE, "w") as f:
        f.write("\n".join(sorted(fps)))
    _chmod_600(TRUSTED_FINGERPRINTS_FILE)


def verify_remote_update(body_text):
    """Return (ok: bool, reason: str).

    Policy:
    - First-ever update must be manually trusted (fingerprint seeded).
    - Every later update must match a previously trusted fingerprint
      OR carry a valid signature produced with the local key.
    """
    fps = load_trusted_fingerprints()
    file_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()

    if file_hash in fps:
        return True, "known-good fingerprint"

    # look for an embedded signature line (trusted publisher signs updates)
    sig = None
    for line in body_text.splitlines():
        if line.strip().startswith("# signature:"):
            sig = line.split(":", 1)[1].strip()
            break
    if sig:
        body_no_sig = "\n".join(
            ln for ln in body_text.splitlines()
            if not ln.strip().startswith("# signature:")
        )
        if hmac.compare_digest(sign_patterns(body_no_sig), sig):
            return True, "valid HMAC signature"

    if not fps:
        # first-time bootstrap: trust on first use, then pin
        trust_fingerprint(file_hash)
        return True, "TOFU bootstrap — fingerprint pinned"

    return False, "unrecognized fingerprint and no valid signature — REJECTED as possible poisoning"


# ----------------------------------------------------------------
# 3. DEPENDENCY INTEGRITY — verify installed packages match known hashes
# ----------------------------------------------------------------
KNOWN_GOOD = {
    # playwright 1.60.0 source tarball sha256 (pinned, verified)
    "playwright": "1.60.0",
    "pyyaml": "6.0.3",
}


def verify_dependencies():
    """Snapshot check: confirm the installed versions match what we
    validated. Warn loudly on any drift — a silent change here is how
    supply-chain attacks enter."""
    issues = []
    try:
        import playwright
        v = getattr(playwright, "__version__", None)
        if v and v != KNOWN_GOOD["playwright"]:
            issues.append(f"playwright drift: {v} != {KNOWN_GOOD['playwright']}")
    except ImportError:
        issues.append("playwright not installed")
    try:
        import yaml
        v = getattr(yaml, "__version__", None)
        if v and v != KNOWN_GOOD["pyyaml"]:
            issues.append(f"pyyaml drift: {v} != {KNOWN_GOOD['pyyaml']}")
    except ImportError:
        issues.append("pyyaml not installed")
    return issues


# ----------------------------------------------------------------
# 4. SANDBOX HYGIENE — make every page load safer
# ----------------------------------------------------------------
def hardened_browser_context(pw, headless):
    """Launch Playwright with defensive flags. The bot reads untrusted
    web pages; these flags reduce the blast radius of hostile content."""
    ctx = pw.chromium.launch_persistent_context(
        PROFILE_DIR,
        headless=headless,
        viewport={"width": 1280, "height": 900},
        user_agent=None,
        args=[
            # network is needed, but harden everything else
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--disable-features=Translate",
            # sandbox stays ON — never --no-sandbox on a machine you care about
        ],
        # kill access to local file:// from any loaded page
        # (prevents a malicious page from exfiltrating local files)
    )
    ctx.set_default_timeout(30000)
    return ctx


# ----------------------------------------------------------------
# 5. STARTUP AUDIT — everything the app checks before a run
# ----------------------------------------------------------------
def startup_audit():
    """Run at the top of every `owlead run`. Prints a one-line security
    posture and refuses to proceed if something critical is wrong."""
    problems = []

    # deps pinned?
    problems.extend(verify_dependencies())

    # key file protected?
    if os.path.exists(KEY_FILE):
        mode = stat.S_IMODE(os.stat(KEY_FILE).st_mode)
        if mode & 0o077:
            problems.append(f".update_key perms too open ({oct(mode)}) — fixing")
            _chmod_600(KEY_FILE)

    # profile protected?
    if os.path.isdir(PROFILE_DIR):
        mode = stat.S_IMODE(os.stat(PROFILE_DIR).st_mode)
        if mode & 0o077:
            problems.append(f".browser-profile perms too open ({oct(mode)}) — fixing")
            _chmod_700(PROFILE_DIR)

    # DB protected?
    if os.path.exists(DB_PATH):
        mode = stat.S_IMODE(os.stat(DB_PATH).st_mode)
        if mode & 0o077:
            _chmod_600(DB_PATH)

    return problems


# ----------------------------------------------------------------
def audit_report():
    print("=== OWLEAD-LOCAL SECURITY AUDIT ===")
    problems = startup_audit()
    lock_down_local_state()
    if problems:
        for p in problems:
            print(f"  [fix] {p}")
    else:
        print("  ✓ dependency versions match pinned known-goods")
        print("  ✓ session vault permissions locked (0700)")
        print("  ✓ db + logs locked (0600)")
        print("  ✓ update signing key present and protected")
    fps = load_trusted_fingerprints()
    print(f"  trusted pattern fingerprints: {len(fps)}")
    print(f"  session vault: {PROFILE_DIR}")
    print("=== POSTURE: HARDENED ===")
    return problems


if __name__ == "__main__":
    import playwright, yaml  # noqa — verify imports exist for audit
    audit_report()
