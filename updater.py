"""Self-updating safety-pattern loader.

Fetches the latest patterns.yaml from the configured remote URL,
compares versions, and hot-swaps the safety brain without a restart.
This is the mechanism that keeps the app current as platforms change
their limits and selectors. If no remote is configured, runs local-only.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_PATTERNS = os.path.join(HERE, "patterns.yaml")
BACKUP_PATTERNS = os.path.join(HERE, "patterns.backup.yaml")
VERSION_FILE = os.path.join(HERE, ".pattern_version")


def _read_version(text):
    m = re.search(r'version:\s*["\']?([\d.]+)', text)
    return m.group(1) if m else "0.0.0"


def _version_tuple(v):
    return tuple(int(x) for x in v.split("."))


def load(path=None):
    """Load patterns from disk. Returns dict."""
    with open(path or LOCAL_PATTERNS) as f:
        return yaml.safe_load(f)


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


class SelfUpdater:
    def __init__(self, patterns=None):
        self.patterns = patterns or load()
        self.log = []

    def _say(self, msg):
        self.log.append(msg)
        print(f"[updater] {msg}")

    def remote_url(self):
        return (self.patterns.get("update", {}) or {}).get("remote_url", "").strip()

    def current_version(self):
        return (self.patterns.get("meta", {}) or {}).get("version", "0.0.0")

    def check_for_update(self):
        """Pull remote patterns.yaml. Returns (changed: bool, new_version: str|None).

        Safe by construction: a failed fetch never destroys the local file.
        Validates the download is parseable YAML with a sane meta.version
        before swapping. Backs up the previous file before replacing.
        For private repos, set GITHUB_TOKEN in your environment — the token
        is read from the environment only, never written into the repo or logs.
        """
        url = self.remote_url()
        if not url:
            return False, None

        headers = {"User-Agent": "owlead-local/1.0"}
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["Accept"] = "application/vnd.github.raw+json"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as r:
                body = r.read().decode("utf-8", "replace")
        except Exception as e:
            self._say(f"fetch failed (offline ok): {e}")
            return False, None

        remote_version = _read_version(body)
        local_version = self.current_version()

        if not remote_version or remote_version == "0.0.0":
            self._say("remote file has no usable version — skipping")
            return False, None

        if _version_tuple(remote_version) <= _version_tuple(local_version):
            self._say(f"up to date (local {local_version} = remote {remote_version})")
            return False, None

        # validate the new file parses before trusting it
        try:
            parsed = yaml.safe_load(body)
            if not isinstance(parsed, dict) or "trust_tiers" not in parsed:
                raise ValueError("missing required 'trust_tiers' key")
        except Exception as e:
            self._say(f"remote file failed validation: {e} — keeping local")
            return False, None

        # back up then swap atomically
        shutil.copy(LOCAL_PATTERNS, BACKUP_PATTERNS)
        tmp = LOCAL_PATTERNS + ".tmp"
        with open(tmp, "w") as f:
            f.write(body)
        os.replace(tmp, LOCAL_PATTERNS)
        with open(VERSION_FILE, "w") as f:
            f.write(remote_version)

        self._say(f"UPDATED {local_version} → {remote_version}")
        return True, remote_version

    def maybe_update(self):
        """Called at startup and on the daily schedule. Hot-swaps in-memory
        patterns when an update lands."""
        changed, new_version = self.check_for_update()
        if changed:
            self.patterns = load()
            self._say(f"active safety patterns → v{new_version}")
            return self.patterns
        return None


if __name__ == "__main__":
    p = load()
    print(f"patterns loaded: version {p['meta']['version']} (updated {p['meta']['updated']})")
    print(f"tiers: {list(p['trust_tiers'].keys())}")
    print(f"update remote: {p['update']['remote_url'] or '(local-only mode)'}")
    SelfUpdater(p).maybe_update()
    print("self-update check complete")
