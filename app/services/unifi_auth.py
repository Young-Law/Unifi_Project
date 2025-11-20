# app/services/unifi_auth.py
import os
import time
import logging
import requests
from threading import RLock
from dotenv import load_dotenv
from typing import Optional

# -----------------------------
# Load environment variables
# -----------------------------
load_dotenv()  # reads .env in the current folder

logger = logging.getLogger("unifi_auth")

UNIFI_HOST = os.getenv("UNIFI_HOST", "https://192.168.10.1")
UNIFI_USERNAME = os.getenv("UNIFI_USERNAME", "")
UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD", "")
UNIFI_REMEMBER_ME = os.getenv("UNIFI_REMEMBER_ME", "False").lower() in ("1", "true", "yes")
UNIFI_VERIFY_SSL = os.getenv("UNIFI_VERIFY_SSL", "False").lower() in ("1", "true", "yes")
WHOAMI_PATH = "/api/users/self"
LOGIN_PATH = "/api/auth/login"

LOGIN_URL = f"{UNIFI_HOST}{LOGIN_PATH}"
WHOAMI_URL = f"{UNIFI_HOST}{WHOAMI_PATH}"

# -----------------------------
# Global session + lock
# -----------------------------
_session: Optional[requests.Session] = None
_session_user: Optional[dict] = None
_session_expires_at: float = 0
_lock = RLock()  # Reentrant lock to prevent deadlocks

SESSION_TTL = int(os.getenv("UNIFI_SESSION_TTL", "3600"))  # 1 hour default

# -----------------------------
# Helper to create session
# -----------------------------
def _create_session() -> requests.Session:
    s = requests.Session()
    if not UNIFI_VERIFY_SSL:
        import urllib3
        from urllib3.exceptions import InsecureRequestWarning
        urllib3.disable_warnings(InsecureRequestWarning)
    s.verify = UNIFI_VERIFY_SSL
    return s

# -----------------------------
# Probe /api/users/self
# -----------------------------
def _probe_whoami(force_session: Optional[requests.Session] = None) -> bool:
    global _session_user
    s = force_session or _session
    if not s:
        logger.debug("[_probe_whoami] No session available")
        return False

    try:
        resp = s.get(WHOAMI_URL, timeout=8)
        logger.debug(f"[_probe_whoami] Response code: {resp.status_code}")
        if resp.status_code == 200:
            _session_user = resp.json()
            logger.info(
    "WHOAMI probe success, user: %s", 
    _session_user.get("username") if _session_user else "unknown"
)

            return True
        else:
            logger.warning(f"[_probe_whoami] WHOAMI failed {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        logger.exception(f"[_probe_whoami] Exception: {e}")
        return False

# -----------------------------
# Login function
# -----------------------------
def login() -> bool:
    global _session, _session_user, _session_expires_at

    logger.debug("[login] Starting login function")
    if not UNIFI_USERNAME or not UNIFI_PASSWORD:
        logger.error("[login] UniFi credentials not set in .env (UNIFI_USERNAME / UNIFI_PASSWORD).")
        return False

    logger.debug("[login] Trying to acquire lock")
    with _lock:
        logger.debug("[login] Lock acquired")
        try:
            logger.info(f"[login] Attempting UniFi login to {LOGIN_URL}")
            s = _create_session()
            payload = {
                "username": UNIFI_USERNAME,
                "password": UNIFI_PASSWORD,
                "rememberMe": UNIFI_REMEMBER_ME
            }
            resp = s.post(LOGIN_URL, json=payload, timeout=10, verify=UNIFI_VERIFY_SSL)
            logger.info(f"[login] POST response code: {resp.status_code}")

            if resp.status_code != 200:
                logger.error(f"[login] UniFi login failed ({resp.status_code}): {resp.text[:300]}")
                return False

            _session = s
            logger.debug("[login] Session object saved")

            # Immediately probe /api/users/self
            whoami_ok = _probe_whoami(force_session=s)
            if not whoami_ok:
                logger.warning("[login] Login succeeded but /api/users/self failed")
                _session = None
                _session_user = None
                return False

            _session_expires_at = time.time() + SESSION_TTL
            logger.info("[login] UniFi login success")
            return True

        except Exception as e:
            logger.exception(f"[login] Exception during login: {e}")
            _session = None
            _session_user = None
            return False

# -----------------------------
# Ensure logged in
# -----------------------------
def ensure_logged_in() -> bool:
    global _session, _session_expires_at
    logger.debug("[ensure_logged_in] Start")

    with _lock:
        if _session is None:
            logger.debug("[ensure_logged_in] No session found, calling login()")
            return login()

        if time.time() > _session_expires_at:
            logger.info("[ensure_logged_in] Session TTL expired, re-login needed")
            if not _probe_whoami():
                logger.debug("[ensure_logged_in] WHOAMI failed, calling login()")
                return login()
            _session_expires_at = time.time() + SESSION_TTL
            return True

        if not _probe_whoami():
            logger.info("[ensure_logged_in] Session probe failed, attempting re-login")
            return login()

        logger.debug("[ensure_logged_in] Session valid")
        return True

# -----------------------------
# Get session / current user
# -----------------------------
def get_session() -> Optional[requests.Session]:
    if ensure_logged_in():
        return _session
    return None

def get_current_user() -> Optional[dict]:
    return _session_user
