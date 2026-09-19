# OWLEAD-LOCAL
A local, self-governing IG + X growth engine. Playwright-driven, human-paced,
safety-governed, and it self-updates its own safety brain.

## What it does
The Owlead feature set, re-built to run on your machine whenever you call it:
- **Source-based targeting** — follow from hashtags, competitor followers, search
- **Follow-back management** — ledger of every follow, auto-unfollows non-reciprocals after the configured window
- **Safety governor** — account-tier daily/hourly caps, quiet hours, burst limits, follow/unfollow same-day lockout, block-signal detection, automatic cooldown + half-pace return after any platform warning
- **Self-updating safety patterns** — `patterns.yaml` is the brain (limits, selectors, escalation). The app fetches a newer version from your GitHub raw URL on startup and daily; new limits/selectors hot-swap without a restart or a code change

## Setup (one time)
```bash
cd ~/owlead-local
pip3 install playwright pyyaml   # playwright already present on this machine
python3 -m playwright install chromium   # already done
```

## First run (log in once, it persists)
The browser profile lives in `.browser-profile/` — you log into Instagram and X ONE
time in the window it opens, and from then on sessions persist. Nothing else to configure.

```bash
cd ~/owlead-local
python3 owlead.py run
```
A Chromium window opens. Log into IG + X if prompted. Close the window when done
(you can Ctrl+C the run). Every `run` after that is already authenticated.

## Daily use
```bash
# add growth sources
python3 owlead.py add-source ig competitor kaestyle        # follow Kaestyle's followers
python3 owlead.py add-source ig hashtag    trapsoul
python3 owlead.py add-source x  hashtag    musicproducer
python3 owlead.py add-source x  competitor 42dugg          # whatever lane

# grow (human-paced, safety-governed)
python3 owlead.py run                        # visible browser — recommended
python3 owlead.py run --headless             # quiet background run
python3 owlead.py run --max-actions 20       # lighter run

# unfollow non-reciprocals who never followed back within 4 days
python3 owlead.py sweep

# see what it did / pending follow-backs / today's caps
python3 owlead.py status

# force-check for a safety-pattern update
python3 owlead.py check-update
```

## Self-updating safety (the anti-ban engine)
All limits/behavior live in `patterns.yaml`:
- **trust tiers** (cold / warm / established) with per-day + per-hour caps
- **hard rules** that never break: no follow+unfollow same day, platform-warning cooldown, quiet hours, burst caps, IG following ceiling, X ratio gap
- **human timing** (gap distributions, long pauses, dwell, type speed)
- **block signals** the app watches for on the page and URL
- **DOM selectors** — these rot as platforms change their layout; that's exactly why this file is updateable

### Turning on remote auto-update
1. Push this folder to a private GitHub repo (`~/owlead-local` → `owlead-local`).
2. Get the raw URL of `patterns.yaml`, e.g.
   `https://raw.githubusercontent.com/Claudiustaylor/owlead-local/main/patterns.yaml`
3. Put that URL into `patterns.yaml` under `update.remote_url`.
4. Done. Every `run` and every `check-update` now pulls the newest safety file.

I push safety updates when platforms change limits or selectors — you never edit code.

## Files
- `owlead.py`        the engine (engines, governor, ledger, discovery, run loop)
- `patterns.yaml`    the safety brain (auto-updates)
- `updater.py`       the self-update machinery
- `owlead.db`        SQLite ledger (actions, follows, sources, state) — created on first run
- `.browser-profile/` persistent logged-in browser profile — created on first run

## Safety notes (read these)
1. **A ban is never 100% preventable.** These methods drastically reduce risk by staying inside community-tested safe ranges *and* reacting self-defensively when the platform warns. But IG/X police automation by ToS.
2. **First week: run it on the `cold` tier** even if your account is older. Trust builds; pace earns.
3. **If a run ever prints a lockout, leave it.** The cooldown is the rescue, the half-pace return is the rebuild.
4. **Visible-browser runs (`run` without `--headless`)** look more human than headless. Use visible.

## Security (read this)
This app holds two logged-in social sessions — treat it like a vault, not a script.

- **Session vault** — `.browser-profile/` is permission-locked to your macOS user (0700). Other users/processes can't read it.
- **DB + logs locked** (0600) — same treatment for your action history.
- **Signed pattern updates** — even if the repo URL were hijacked, a poisoned `patterns.yaml` can't load: updates are fingerprint-pinned and HMAC-signed with a local-only key. First update is trusted-on-first-use, then every later update must match a known fingerprint or a valid signature — otherwise it's rejected and the last-known-good keeps running.
- **Dependency pinning** — on every run the app verifies installed `playwright` and `pyyaml` versions against pinned known-goods and refuses quietly if anything drifted (supply-chain guard).
- **Sandbox stays on** — never `--no-sandbox`. Untrusted pages load in the browser sandbox, and no page ever gets access to `file://`.

**Hard rule (for me and for future edits): NEVER put passwords, API keys, tokens, or session data in code, config files, committed files, or chat.** Secrets live in the environment or the keychain only. If a security control can't be set up with the access currently available: STOP and ask, never improvise. Harden from the default; never soften it to make something work.

**Adversarial-update integrity.** Pattern updates are fingerprint-pinned and HMAC-signed with a local-only key. Trust is seeded ONCE from the local human-verified file at startup — never by trusting remote content. An unsigned, tampered, or forged update is rejected and the last-known-good keeps running. This was attack-tested live: unsigned poison, forged signatures, and tampered payloads all rejected.

Run the audit any time:

```bash
python3 owlead.py security-audit
```
