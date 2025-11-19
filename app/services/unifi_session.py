# app/services/unifi_session.py
import requests, pickle, base64, os
from typing import Optional
from app.db import SessionLocal, StoredSession
import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = os.getenv("UNIFI_BASE", "https://192.168.10.1")
LOGIN_PATH = "/api/auth/login"
WHOAMI_PATH = "/api/users/self"


# -------------------------------------------------------
# Cookie helpers
# -------------------------------------------------------
def serialize_cookiejar_to_b64(cookiejar):
    return base64.b64encode(pickle.dumps(cookiejar)).decode()

def deserialize_cookiejar_from_b64(b64_str):
    return pickle.loads(base64.b64decode(b64_str))


# -------------------------------------------------------
# FIRST STEP OF LOGIN (username/password)
# -------------------------------------------------------
def start_login(username: str, password: str, remember_me: bool = False):
    url = f"{BASE}{LOGIN_PATH}"
    payload = {
        "username": username,
        "password": password,
        "rememberMe": remember_me,
        "token": ""  # no OTP yet
    }
    headers = {"origin": BASE, "content-type": "application/json", "accept": "*/*"}

    s = requests.Session()
    s.verify = False

    try:
        resp = s.post(url, json=payload, headers=headers, timeout=10)
    except Exception as e:
        return {"ok": False, "error": f"request_failed: {e}"}

    try:
        body = resp.json()
    except:
        body = {}

    # If 200: Logged in WITHOUT MFA (rare)
    if resp.status_code == 200:
        csrf = resp.headers.get("x-csrf-token")
        return {
            "ok": True,
            "mfa_required": False,
            "cookiejar_b64": serialize_cookiejar_to_b64(s.cookies),
            "csrf": csrf
        }

    # If MFA required
    if body.get("code") == "MFA_AUTH_REQUIRED":
        data = body.get("data", {})
        return {
            "ok": True,
            "mfa_required": True,
            "mfa_cookie": data.get("mfaCookie"),
            "authenticators": data.get("authenticators", []),
            "cookiejar_b64": serialize_cookiejar_to_b64(s.cookies)  # store this!
        }

    # Otherwise error
    return {"ok": False, "status": resp.status_code, "body": body}


# -------------------------------------------------------
# SECOND STEP OF LOGIN — COMPLETE MFA
# -------------------------------------------------------
def complete_login(
    username: str,
    password: str,
    token: str,
    cookiejar_b64: str,
    remember_me: bool = False,
    mfa_cookie: Optional[str] = None
):
    url = f"{BASE}{LOGIN_PATH}"

    payload = {
        "username": username,
        "password": password,
        "rememberMe": remember_me,
        "token": token
    }
    headers = {"origin": BASE, "content-type": "application/json", "accept": "*/*"}

    s = requests.Session()
    s.verify = False

    #  RESTORE COOKIES FROM STEP 1
    try:
        jar = deserialize_cookiejar_from_b64(cookiejar_b64)
        s.cookies.update(jar)
    except Exception as e:
        return {"ok": False, "error": f"cookie_restore_failed: {e}"}

    # Add MFA cookie
    if mfa_cookie:
        try:
            if "=" in mfa_cookie:
                k, v = mfa_cookie.split("=", 1)
                s.cookies.set(k, v, domain="192.168.10.1")
            else:
                headers["cookie"] = mfa_cookie
        except:
            headers["cookie"] = mfa_cookie

    # Call login again but now with OTP
    try:
        resp = s.post(url, json=payload, headers=headers, timeout=10)
    except Exception as e:
        return {"ok": False, "error": f"request_failed: {e}"}

    try:
        body = resp.json()
    except:
        body = {}

    # SUCCESS 200
    if resp.status_code == 200:
        csrf = resp.headers.get("x-csrf-token")
        cookiejar = s.cookies

        # Save to DB
        db = SessionLocal()
        try:
            blob = pickle.dumps(cookiejar)
            existing = db.query(StoredSession).filter(StoredSession.username == username).first()
            now = datetime.datetime.utcnow()

            if existing:
                existing.cookie_pickle = blob
                existing.csrf_token = csrf
                existing.last_seen = now
                db.add(existing)
                session_obj = existing
            else:
                session_obj = StoredSession(
                    username=username,
                    cookie_pickle=blob,
                    csrf_token=csrf,
                    created_at=now,
                    last_seen=now,
                    expires_at=None
                )
                db.add(session_obj)

            db.commit()

            return {"ok": True, "db_id": session_obj.id, "csrf": bool(csrf)}

        except Exception as e:
            db.rollback()
            return {"ok": False, "error": f"db_error: {e}"}
        finally:
            db.close()

    # FAILURE
    return {"ok": False, "status": resp.status_code, "body": body}


# Utility: check whoami with the latest stored session (returns True/False)
def check_any_session_valid():
    db = SessionLocal()
    try:
        row = db.query(StoredSession).order_by(StoredSession.last_seen.desc()).first()
        if not row:
            return {"ok": False, "reason": "no_session"}

        # load cookie jar from pickle
        cookiejar = pickle.loads(row.cookie_pickle)

        s = requests.Session()
        s.verify = False
        s.cookies.update(cookiejar)
        headers = {}
        if row.csrf_token:
            headers["x-csrf-token"] = row.csrf_token

        try:
            r = s.get(f"{BASE}{WHOAMI_PATH}", headers=headers, timeout=8)
            if r.status_code == 200:
                row.last_seen = datetime.datetime.utcnow()
                db.add(row)
                db.commit()
                return {"ok": True, "db_id": row.id, "user": r.json()}
            else:
                return {"ok": False, "status": r.status_code}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    finally:
        db.close()

def get_active_session_auth():
    """
    Returns (headers, cookies) for UniFi API using
    the most recently stored UniFi session.
    """
    db = SessionLocal()
    try:
        row = db.query(StoredSession).order_by(StoredSession.last_seen.desc()).first()
        if not row:
            return None, None

        # Load cookie jar from DB
        cookiejar = pickle.loads(row.cookie_pickle)

        # Convert CookieJar → dict for requests
        cookies_dict = {c.name: c.value for c in cookiejar}

        headers = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json;charset=UTF-8",
            "x-csrf-token": row.csrf_token or "",
        }

        return headers, cookies_dict

    finally:
        db.close()
