# app.py
from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import time
import threading
import traceback
import urllib3

import like_pb2
import uid_generator_pb2
import visit_count_pb2
from google.protobuf.message import DecodeError
from collections import OrderedDict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# =========================================================
# CONFIG
# =========================================================
DAILY_LIMIT = 300
used_count = 0
used_count_lock = threading.Lock()

CACHE_DURATION = 120

REQ_TIMEOUT = 30
CHECK_TIMEOUT = 20
CHECK_CONCURRENCY = 15
CHECK_RETRIES = 2

# How many concurrent like requests at once (avoid IP ban)
LIKE_CONCURRENCY = 50

UA_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB55",
}

account_status_cache = {
    "last_check": 0,
    "region": None,
    "total_accounts": 0,
    "active_accounts": 0,
    "inactive_accounts": 0,
    "active_uids": [],
    "inactive_uids": [],
    "details": [],
    "checking": False,
    "last_error": None,
}
_cache_lock = threading.Lock()


# =========================================================
# FILE LOADERS
# =========================================================
REGION_FILES = {
    "IND": {"uid": "Uid_ind.json", "token": "token_ind.json"},
    "BR":  {"uid": "Uid_br.json",  "token": "token_br.json"},
    "US":  {"uid": "Uid_br.json",  "token": "token_br.json"},
    "SAC": {"uid": "Uid_br.json",  "token": "token_br.json"},
    "NA":  {"uid": "Uid_br.json",  "token": "token_br.json"},
    "BD":  {"uid": "Uid_bd.json",  "token": "token_bd.json"},
}


def _files_for(region: str):
    return REGION_FILES.get(region.upper(), REGION_FILES["BD"])


def load_tokens(region):
    fname = _files_for(region)["token"]
    try:
        with open(fname, "r", encoding="utf-8") as f:
            tokens = json.load(f)
        if not isinstance(tokens, list) or not tokens:
            app.logger.error(f"{fname}: empty or not a list")
            return None
        return tokens
    except FileNotFoundError:
        app.logger.error(f"Token file not found: {fname}")
        return None
    except Exception as e:
        app.logger.error(f"Error loading {fname}: {e}")
        return None


def load_accounts(region):
    fname = _files_for(region)["uid"]
    try:
        with open(fname, "r", encoding="utf-8") as f:
            accounts = json.load(f)
        if not isinstance(accounts, list) or not accounts:
            app.logger.error(f"{fname}: empty or not a list")
            return None
        return accounts
    except FileNotFoundError:
        app.logger.error(f"Account file not found: {fname}")
        return None
    except Exception as e:
        app.logger.error(f"Error loading {fname}: {e}")
        return None


# =========================================================
# CRYPTO + PROTOBUF
# =========================================================
_AES_KEY = b"Yg&tc%DEuh6%Zc^8"
_AES_IV = b"6oyZDr22E3ychjM%"


def encrypt_message(plaintext: bytes):
    try:
        cipher = AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV)
        padded = pad(plaintext, AES.block_size)
        return binascii.hexlify(cipher.encrypt(padded)).decode("utf-8")
    except Exception as e:
        app.logger.error(f"encrypt_message: {e}")
        return None


def create_protobuf_message(user_id, region):
    try:
        msg = like_pb2.like()
        msg.uid = int(user_id)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"like protobuf: {e}")
        return None


def create_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"uid protobuf: {e}")
        return None


def enc(uid):
    pb = create_protobuf(uid)
    if pb is None:
        return None
    return encrypt_message(pb)


# =========================================================
# ENDPOINTS PER REGION
# =========================================================
def get_endpoint(region: str, path: str) -> str:
    region = region.upper()
    if region == "IND":
        return f"https://client.ind.freefiremobile.com/{path}"
    if region in {"BR", "US", "SAC", "NA"}:
        return f"https://client.us.freefiremobile.com/{path}"
    return f"https://clientbp.ggpolarbear.com/{path}"


# =========================================================
# SYNC HTTP (before/after snapshot)
# =========================================================
def make_request(encrypted_hex, region, token, retries=None, timeout=None):
    if retries is None:
        retries = CHECK_RETRIES
    if timeout is None:
        timeout = REQ_TIMEOUT

    url = get_endpoint(region, "GetPlayerPersonalShow")
    headers = dict(UA_HEADERS)
    headers["Authorization"] = f"Bearer {token}"
    payload = bytes.fromhex(encrypted_hex)

    last_err = None
    for attempt in range(retries + 1):
        try:
            r = requests.post(
                url, data=payload, headers=headers,
                verify=False, timeout=timeout,
            )
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
                app.logger.warning(f"GetPlayerPersonalShow {last_err}")
            else:
                decoded = visit_count_pb2.Info()
                decoded.ParseFromString(r.content)
                return decoded
        except DecodeError as e:
            last_err = f"DecodeError: {e}"
            app.logger.error(last_err)
        except (requests.Timeout, requests.ConnectionError) as e:
            last_err = f"{type(e).__name__}: {e}"
            app.logger.warning(f"make_request attempt {attempt+1}/{retries+1}: {last_err}")
        except Exception as e:
            last_err = str(e)
            app.logger.error(f"make_request: {last_err}")

        if attempt < retries:
            time.sleep(1.5 * (attempt + 1))

    app.logger.error(f"make_request gave up: {last_err}")
    return None


# =========================================================
# ASYNC HTTP
# =========================================================
async def _post_async(session, url, payload: bytes, token: str, timeout: int):
    headers = dict(UA_HEADERS)
    headers["Authorization"] = f"Bearer {token}"
    async with session.post(
        url, data=payload, headers=headers,
        timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
    ) as resp:
        return resp.status, await resp.read()


async def send_request(session, encrypted_hex, token, url):
    try:
        status, _ = await _post_async(
            session, url, bytes.fromhex(encrypted_hex), token, REQ_TIMEOUT
        )
        return status
    except Exception as e:
        app.logger.debug(f"send_request: {e}")
        return None


# =========================================================
# FIXED: fan out using ALL tokens by default
# =========================================================
async def send_multiple_requests(uid, region, url, count=None, concurrency=LIKE_CONCURRENCY):
    """
    Fire like requests using tokens round-robin.
    - count=None  -> use ALL tokens once (your 250)
    - count=N     -> fire exactly N requests (loops tokens if N > 250)
    - concurrency -> max in-flight at once
    """
    try:
        pb = create_protobuf_message(uid, region)
        if pb is None:
            return None
        enc_uid = encrypt_message(pb)
        if enc_uid is None:
            return None

        tokens = load_tokens(region)
        if not tokens:
            return None

        token_list = [t["token"] for t in tokens if t.get("token")]
        if not token_list:
            return None

        n = len(token_list) if count is None else max(1, int(count))
        app.logger.info(f"[like] target={uid} tokens={len(token_list)} requests={n} conc={concurrency}")

        sem = asyncio.Semaphore(concurrency)

        async def one(session, tok):
            async with sem:
                return await send_request(session, enc_uid, tok, url)

        async with aiohttp.ClientSession() as session:
            tasks = [
                one(session, token_list[i % len(token_list)])
                for i in range(n)
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"send_multiple_requests: {e}")
        return None


# =========================================================
# ACCOUNT HEALTH CHECK
# =========================================================
async def check_token_async(session, token, uid, region):
    try:
        pb = create_protobuf(uid)
        if pb is None:
            return {"uid": uid, "active": False, "error": "protobuf"}
        encrypted = encrypt_message(pb)
        if encrypted is None:
            return {"uid": uid, "active": False, "error": "encrypt"}

        url = get_endpoint(region, "GetPlayerPersonalShow")
        payload = bytes.fromhex(encrypted)

        last_err = None
        for attempt in range(CHECK_RETRIES + 1):
            try:
                status, body = await _post_async(
                    session, url, payload, token, CHECK_TIMEOUT
                )
                if status != 200:
                    last_err = f"HTTP {status}"
                else:
                    try:
                        decoded = visit_count_pb2.Info()
                        decoded.ParseFromString(body)
                        nick = decoded.AccountInfo.PlayerNickname
                        if nick:
                            return {
                                "uid": uid, "active": True,
                                "nickname": nick,
                                "level": decoded.AccountInfo.Levels,
                            }
                        last_err = "empty nickname"
                    except Exception as e:
                        last_err = f"parse: {e}"
            except asyncio.TimeoutError:
                last_err = "timeout"
            except aiohttp.ClientError as e:
                last_err = f"ClientError: {type(e).__name__}"
            except Exception as e:
                last_err = str(e)[:80]

            if attempt < CHECK_RETRIES:
                await asyncio.sleep(1.0 * (attempt + 1))

        return {"uid": uid, "active": False, "error": last_err or "unknown"}
    except Exception as e:
        return {"uid": uid, "active": False, "error": str(e)[:80]}


async def check_all_accounts_async(region, accounts, tokens):
    token_list = [t["token"] for t in tokens if t.get("token")]
    if not token_list:
        return [], [], []

    sem = asyncio.Semaphore(CHECK_CONCURRENCY)

    async def worker(session, tok, u):
        async with sem:
            return await check_token_async(session, tok, u, region)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, acc in enumerate(accounts):
            u = str(acc.get("uid", "")).strip()
            if not u:
                continue
            tasks.append(worker(session, token_list[i % len(token_list)], u))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    active, inactive, details = [], [], []
    for r in results:
        if isinstance(r, Exception) or not isinstance(r, dict):
            continue
        if r.get("active"):
            active.append(r["uid"])
            details.append({
                "uid": r["uid"], "status": "active",
                "nickname": r.get("nickname", ""),
                "level": r.get("level", 0),
            })
        else:
            inactive.append(r["uid"])
            details.append({
                "uid": r["uid"], "status": "inactive",
                "error": r.get("error", "unknown"),
            })
    return active, inactive, details


def run_status_check(region, force=False):
    with _cache_lock:
        if account_status_cache["checking"]:
            return
        cache_age = time.time() - account_status_cache["last_check"]
        if (
            not force
            and account_status_cache["region"] == region
            and account_status_cache["total_accounts"] > 0
            and cache_age < CACHE_DURATION
        ):
            return
        account_status_cache["checking"] = True
        account_status_cache["last_error"] = None

    print(f"\n[status] === Checking region {region} ===")
    try:
        accounts = load_accounts(region)
        if not accounts:
            raise RuntimeError(f"{_files_for(region)['uid']} missing or empty")
        print(f"[status] Loaded {len(accounts)} accounts")

        tokens = load_tokens(region)
        if not tokens:
            raise RuntimeError(f"{_files_for(region)['token']} missing or empty")
        print(f"[status] Loaded {len(tokens)} tokens")

        active, inactive, details = asyncio.run(
            check_all_accounts_async(region, accounts, tokens)
        )

        with _cache_lock:
            account_status_cache.update({
                "last_check": time.time(),
                "region": region,
                "total_accounts": len(accounts),
                "active_accounts": len(active),
                "inactive_accounts": len(inactive),
                "active_uids": active,
                "inactive_uids": inactive,
                "details": details,
                "checking": False,
            })
        print(f"[status] OK — Active: {len(active)} / {len(accounts)} (inactive: {len(inactive)})")
    except Exception as e:
        tb = traceback.format_exc()
        app.logger.error(f"Status check failed: {e}\n{tb}")
        print(f"[status] FAILED: {e}")
        with _cache_lock:
            account_status_cache["checking"] = False
            account_status_cache["last_error"] = str(e)


# =========================================================
# ROUTES
# =========================================================
@app.route("/like", methods=["GET"])
def handle_like():
    global used_count

    uid = request.args.get("uid")
    region = (request.args.get("region") or "").upper()
    if not uid or not region:
        return {"error": "UID and region are required"}, 400

    # count = how many like requests to fire. Default = all tokens.
    count_arg = request.args.get("count")
    count = int(count_arg) if count_arg and count_arg.isdigit() else None

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens.")

        token = tokens[0]["token"]
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            raise Exception("Encryption of UID failed.")

        before = make_request(encrypted_uid, region, token)
        if before is None:
            raise Exception("Failed to get initial info.")
        before_like = before.AccountInfo.Likes

        url = get_endpoint(region, "LikeProfile")
        asyncio.run(send_multiple_requests(uid, region, url, count=count))

        after = make_request(encrypted_uid, region, token)
        if after is None:
            raise Exception("Failed to get final info.")

        after_like = after.AccountInfo.Likes
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        if status == 1:
            with used_count_lock:
                used_count += 1

        with used_count_lock:
            used = used_count
        remaining = max(DAILY_LIMIT - used, 0)

        result = OrderedDict([
            ("LikesGivenByAPI", like_given),
            ("LikesafterCommand", after_like),
            ("LikesbeforeCommand", before_like),
            ("PlayerNickname", after.AccountInfo.PlayerNickname),
            ("Level", after.AccountInfo.Levels),
            ("Region", after.AccountInfo.PlayerRegion),
            ("UID", after.AccountInfo.UID),
            ("status", status),
            ("requests_sent", count if count else len(tokens)),
            ("tokens_loaded", len(tokens)),
            ("daily_limit", DAILY_LIMIT),
            ("used", used),
            ("remaining", remaining),
        ])
        return app.response_class(
            response=json.dumps(result, separators=(",", ":")),
            status=200,
            mimetype="application/json",
        )
    except Exception as e:
        app.logger.error(f"/like error: {e}")
        return {"error": str(e)}, 500


@app.route("/remain", methods=["GET"])
def remain_info():
    with used_count_lock:
        used = used_count
    return jsonify({
        "daily_limit": DAILY_LIMIT,
        "remaining": max(DAILY_LIMIT - used, 0),
        "used": used,
        "reset_info": "4:00 AM IST",
    })


@app.route("/accounts/count", methods=["GET"])
def accounts_count():
    region = (request.args.get("region") or "BD").upper()
    refresh = request.args.get("refresh", "0") == "1"

    cache_age = time.time() - account_status_cache["last_check"]
    cache_ok = (
        not refresh
        and account_status_cache["region"] == region
        and account_status_cache["total_accounts"] > 0
        and cache_age < CACHE_DURATION
    )
    if not cache_ok:
        run_status_check(region, force=refresh)

    return jsonify({
        "region": region,
        "total_accounts": account_status_cache["total_accounts"],
        "active_accounts": account_status_cache["active_accounts"],
        "inactive_accounts": account_status_cache["inactive_accounts"],
        "ready_to_like": account_status_cache["active_accounts"],
        "checking": account_status_cache["checking"],
        "last_check": (
            time.strftime("%Y-%m-%d %H:%M:%S",
                          time.localtime(account_status_cache["last_check"]))
            if account_status_cache["last_check"] else None
        ),
        "cache_age_seconds": round(cache_age, 1),
        "last_error": account_status_cache["last_error"],
    })


@app.route("/accounts/status", methods=["GET"])
def accounts_status():
    region = (request.args.get("region") or "BD").upper()
    refresh = request.args.get("refresh", "0") == "1"
    include_details = request.args.get("details", "0") == "1"

    cache_age = time.time() - account_status_cache["last_check"]
    cache_ok = (
        not refresh
        and account_status_cache["region"] == region
        and account_status_cache["total_accounts"] > 0
        and cache_age < CACHE_DURATION
    )
    if not cache_ok:
        run_status_check(region, force=refresh)

    out = {
        "region": region,
        "total_accounts": account_status_cache["total_accounts"],
        "active_accounts": account_status_cache["active_accounts"],
        "inactive_accounts": account_status_cache["inactive_accounts"],
        "ready_to_like": account_status_cache["active_accounts"],
        "checking": account_status_cache["checking"],
        "last_check": (
            time.strftime("%Y-%m-%d %H:%M:%S",
                          time.localtime(account_status_cache["last_check"]))
            if account_status_cache["last_check"] else None
        ),
        "cache_age_seconds": round(cache_age, 1),
        "last_error": account_status_cache["last_error"],
    }
    if include_details:
        out["active_uids"] = account_status_cache["active_uids"]
        out["inactive_uids"] = account_status_cache["inactive_uids"]
        out["details"] = account_status_cache["details"]
    return jsonify(out)


# =========================================================
# STARTUP
# =========================================================
def _warm_cache():
    time.sleep(3)
    try:
        run_status_check("BD", force=False)
    except Exception as e:
        print(f"[warm] failed: {e}")


if __name__ == "__main__":
    threading.Thread(target=_warm_cache, daemon=True).start()
    app.run(debug=False, use_reloader=False, host="0.0.0.0", port=5000)