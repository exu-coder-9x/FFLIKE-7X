# main.py
import json
import os
import sys
import time
from pathlib import Path

import requests

# ---------- Paths (ALWAYS relative to this file) ----------
BASE_DIR = Path(__file__).resolve().parent
UID_FILE = BASE_DIR / "Uid_bd.json"
TOKEN_FILE = BASE_DIR / "token_bd.json"

# Force all relative opens to resolve inside this project folder
os.chdir(BASE_DIR)

# ---------- Config ----------
JWT_API_URL = os.getenv("JWT_API_URL", "https://arafat-jwt-obb.vercel.app/token").strip()
JWT_API_METHOD = os.getenv("JWT_API_METHOD", "GET").upper()
JWT_API_TIMEOUT = float(os.getenv("JWT_API_TIMEOUT", "30"))
JWT_API_DELAY = float(os.getenv("JWT_API_DELAY", "0.15"))

AUTO_START_SERVER = os.getenv("AUTO_START_SERVER", "1") == "1"
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))

# Set FORCE_REGEN=1 to always rebuild tokens even if file exists
FORCE_REGEN = os.getenv("FORCE_REGEN", "0") == "1"

# Minimum valid tokens required before skipping generation
MIN_TOKENS_OK = int(os.getenv("MIN_TOKENS_OK", "1"))


# ---------- Helpers ----------
def banner(msg):
    print(f"\n{'=' * 60}\n{msg}\n{'=' * 60}")


def progress_bar(done, total, width=30):
    filled = int(width * done / total) if total else 0
    bar = "█" * filled + "░" * (width - filled)
    pct = (done / total * 100) if total else 0
    return f"[{bar}] {pct:5.1f}%  ({done}/{total})"


def extract_token(data):
    if isinstance(data, str) and data.strip():
        return data.strip()
    if isinstance(data, dict):
        for key in ("jwt_token", "token", "access_token", "jwt"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        for key in ("data", "result", "response"):
            if key in data:
                v = extract_token(data[key])
                if v:
                    return v
    if isinstance(data, list):
        for item in data:
            v = extract_token(item)
            if v:
                return v
    return None


def get_token(uid, password, session):
    params = {"uid": uid, "password": password}
    headers = {"Accept": "application/json", "User-Agent": "OB55-Token-Gen/1.0"}

    if JWT_API_METHOD == "POST":
        r = session.post(JWT_API_URL, json=params, headers=headers, timeout=JWT_API_TIMEOUT)
    else:
        r = session.get(JWT_API_URL, params=params, headers=headers, timeout=JWT_API_TIMEOUT)

    r.raise_for_status()
    try:
        data = r.json()
    except ValueError:
        data = r.text

    token = extract_token(data)
    if not token:
        raise ValueError("no token in response")
    return token


# ---------- Token file validation ----------
def token_file_status():
    """
    Returns (exists, valid, count, reason).
      exists : file is present on disk
      valid  : file is a JSON list of >=MIN_TOKENS_OK dicts with a 'token' key
      count  : number of valid token entries
      reason : short human-readable explanation
    """
    if not TOKEN_FILE.exists():
        return False, False, 0, "file does not exist"

    try:
        raw = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except Exception as e:
        return True, False, 0, f"cannot read: {e}"

    if not raw:
        return True, False, 0, "file is empty"

    try:
        data = json.loads(raw)
    except Exception as e:
        return True, False, 0, f"invalid JSON: {e}"

    if not isinstance(data, list):
        return True, False, 0, f"top-level is {type(data).__name__}, expected list"

    valid = [d for d in data if isinstance(d, dict) and isinstance(d.get("token"), str) and d["token"].strip()]

    if len(valid) < MIN_TOKENS_OK:
        return True, False, len(valid), f"only {len(valid)} valid tokens (need ≥{MIN_TOKENS_OK})"

    return True, True, len(valid), "ok"


# ---------- Generation ----------
def generate_all_tokens():
    if not UID_FILE.exists():
        print(f"ERROR: {UID_FILE} not found", file=sys.stderr)
        return None

    accounts = json.loads(UID_FILE.read_text(encoding="utf-8"))
    if not isinstance(accounts, list) or not accounts:
        print("ERROR: Uid_bd.json must be a non-empty JSON list", file=sys.stderr)
        return None

    total = len(accounts)
    banner(f"🔑 Generating JWT tokens for {total} accounts")

    session = requests.Session()
    tokens = []
    failed = []
    started = time.time()

    for i, acc in enumerate(accounts, 1):
        uid = str(acc.get("uid", "")).strip()
        pwd = str(acc.get("password", "")).strip()

        if not uid or not pwd:
            failed.append((uid or "?", "missing uid/password"))
            print(f"\r{progress_bar(i, total)}  ⚠  {uid or '?'} missing fields", end="")
            continue

        try:
            token = get_token(uid, pwd, session)
            tokens.append({"token": token})
            print(f"\r{progress_bar(i, total)}  ✅ {uid}", end="")
        except Exception as e:
            failed.append((uid, str(e)[:60]))
            print(f"\r{progress_bar(i, total)}  ❌ {uid} - {str(e)[:50]}", end="")

        if JWT_API_DELAY > 0:
            time.sleep(JWT_API_DELAY)

    print()
    elapsed = time.time() - started

    banner("📊 TOKEN GENERATION SUMMARY")
    print(f"  Total accounts      : {total}")
    print(f"  ✅ Tokens generated : {len(tokens)}")
    print(f"  ❌ Failed           : {len(failed)}")
    print(f"  ⏱  Time elapsed     : {elapsed:.1f}s")
    if total:
        print(f"  ⚡ Avg per account  : {elapsed/total:.2f}s")

    if failed:
        print("\n  Failed accounts (first 20):")
        for uid, err in failed[:20]:
            print(f"    - {uid}: {err}")
        if len(failed) > 20:
            print(f"    ... and {len(failed) - 20} more")

    if not tokens:
        print("\n❌ No tokens generated. Aborting.", file=sys.stderr)
        return None

    # Atomic write
    tmp = TOKEN_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(tokens, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
    tmp.replace(TOKEN_FILE)

    # Verify
    _, valid, cnt, reason = token_file_status()
    print(f"\n💾 Saved to: {TOKEN_FILE.resolve()}")
    print(f"   File size: {TOKEN_FILE.stat().st_size / 1024:.1f} KB")
    if valid:
        print(f"   ✅ Verified: {cnt} tokens on disk")
    else:
        print(f"   ❌ Verification failed: {reason}", file=sys.stderr)
        return None

    return tokens


# ---------- Server ----------
def start_server():
    banner(f"🚀 Starting Flask server on http://{SERVER_HOST}:{SERVER_PORT}")
    print("  Endpoints:")
    print("    GET  /like?uid=<uid>&region=BD")
    print("    GET  /remain")
    print("    GET  /accounts/count?region=BD")
    print("    GET  /accounts/status?region=BD&details=1")
    print(f"\n  Working dir: {Path.cwd()}")
    print(f"  Token file : {TOKEN_FILE.resolve()}")
    print("\n  Press Ctrl+C to stop.\n")

    from wsgi import app
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False, use_reloader=False)


# ---------- Main ----------
if __name__ == "__main__":
    banner("🔥 FFLIKE-7X — Token Generator + Server")
    print(f"  Base dir   : {BASE_DIR}")
    print(f"  UID file   : {UID_FILE}")
    print(f"  Token file : {TOKEN_FILE}")
    print(f"  JWT API    : {JWT_API_URL}  [{JWT_API_METHOD}]")

    exists, valid, count, reason = token_file_status()

    print(f"\n📁 token_bd.json status: exists={exists}  valid={valid}  count={count}  ({reason})")

    need_regen = FORCE_REGEN or not valid

    if not need_regen:
        print(f"✅ Using existing {TOKEN_FILE.name} with {count} tokens.")
        print("   (Set FORCE_REGEN=1 to rebuild anyway)")
    else:
        if FORCE_REGEN:
            print("⚙  FORCE_REGEN=1 → regenerating tokens...")
        elif not exists:
            print("📝 token_bd.json not found → generating fresh tokens...")
        else:
            print(f"⚠  token_bd.json is invalid ({reason}) → regenerating tokens...")

        tokens = generate_all_tokens()
        if tokens is None:
            print("\n⚠  Token generation failed. Server not started.", file=sys.stderr)
            sys.exit(1)

    # Final pre-flight check
    exists, valid, count, reason = token_file_status()
    if not valid:
        print(f"\n❌ CRITICAL: {TOKEN_FILE} is not usable ({reason}).", file=sys.stderr)
        print(f"   Absolute path: {TOKEN_FILE.resolve()}", file=sys.stderr)
        sys.exit(1)

    print(f"\n✅ Ready. {count} tokens at {TOKEN_FILE.resolve()}")

    if AUTO_START_SERVER:
        time.sleep(1)
        start_server()
    else:
        print("\n✅ Done. (AUTO_START_SERVER=0, not launching Flask.)")
        print("   Run `python wsgi.py` to start the server.")
