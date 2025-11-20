# app/services/unifi_service.py
import logging
import os
import requests
from app.services.unifi_auth import get_session, ensure_logged_in, get_current_user
import json
import base64


logger = logging.getLogger("unifi_service")
logger.setLevel(logging.DEBUG)


UNIFI_HOST = os.getenv("UNIFI_HOST", "https://192.168.10.1")
BASE_URL = f"{UNIFI_HOST}/proxy/network/v2/api/site/default"
TRAFFIC_RULES_PATH = "trafficrules"
CLIENTS_ACTIVE_PATH = "clients/active?includeTrafficUsage=true&includeUnifiDevices=true"
CLIENTS_HISTORY_PATH = "clients/history?includeUnifiDevices=true&onlyNonBlocked=false&withinHours=87600"


def _get_session_or_warn():
    s = get_session()
    if not s:
        logger.warning("No valid UniFi session (get_session returned None)")
    return s


def get_traffic_rules():
    s = _get_session_or_warn()
    if not s:
        return []

    url = f"{BASE_URL}/{TRAFFIC_RULES_PATH}"
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
        logger.info("Fetched traffic rules successfully")
        return resp.json()  # keep original response shape
    except Exception as e:
        logger.error(f"Error fetching traffic rules - {e}")
        return []

def update_traffic_rule(rule_id: str, new_action: str):
    """
    Update a UniFi traffic rule ('ALLOW' or 'BLOCK') by sending PUT to the individual rule endpoint.
    Returns updated rule dict on success, None otherwise.
    """
    s = get_session()
    if not s:
        logger.warning("No valid UniFi session available.")
        return None

    try:
        # 1. Get the full rule
        rule = get_rule_by_id(rule_id)
        if not rule:
            logger.error(f"Rule {rule_id} not found")
            return None

        old_action = rule.get("action", "UNKNOWN")
        rule["action"] = new_action.upper()

        # 2. Extract CSRF token from JWT cookie
        token = s.cookies.get("TOKEN")
        if not token:
            logger.error("No TOKEN cookie found in session. Cannot update rule.")
            return None

        csrf_token = token
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                decoded = base64.b64decode(payload)
                jwt_data = json.loads(decoded)
                csrf_token = jwt_data.get("csrfToken", token)
        except Exception:
            pass

        headers = {
            "accept": "application/json, text/plain, */*",
            "content-type": "application/json",
            "x-csrf-token": csrf_token,
            "origin": UNIFI_HOST,
            "referer": f"{UNIFI_HOST}/",
        }

        # 3. PUT to the individual rule endpoint (like working script)
        url_put = f"{BASE_URL}/{TRAFFIC_RULES_PATH}/{rule_id}"
        logger.debug(f"PUT URL: {url_put}")
        logger.debug(f"Payload keys: {list(rule.keys())}")

        put_resp = s.put(url_put, json=rule, headers=headers, timeout=10, verify=False)
        put_resp.raise_for_status()

        logger.info(f"Rule {rule_id} updated successfully: {old_action} - {new_action.upper()}")
        return put_resp.json()

    except requests.HTTPError as http_err:
        logger.error(f"HTTP error updating rule {rule_id}: {http_err}")
        if http_err.response is not None:
            logger.debug(f"Response status: {http_err.response.status_code}")
            logger.debug(f"Response content: {http_err.response.text}")
    except Exception as e:
        logger.exception(f"Failed to update traffic rule {rule_id}: {e}")

    return None





def get_rule_by_id(rule_id: str):
    rules = get_traffic_rules()
    if not isinstance(rules, list):
        # older code sometimes expects a list; handle both shapes
        try:
            # some responses return {"data": [...]}
            rules_list = rules.get("data", [])
        except Exception:
            rules_list = []
    else:
        rules_list = rules

    for rule in rules_list:
        if rule.get("_id") == rule_id:
            return rule
    logger.warning(f"Rule not found - {rule_id}")
    return None


def get_active_clients():
    s = _get_session_or_warn()
    if not s:
        return []

    url = f"{BASE_URL}/{CLIENTS_ACTIVE_PATH}"
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
        logger.info("Fetched active clients")
        return resp.json()
    except Exception as e:
        logger.error(f"Error fetching active clients - {e}")
        return []


def get_history_clients():
    s = _get_session_or_warn()
    if not s:
        return []

    url = f"{BASE_URL}/{CLIENTS_HISTORY_PATH}"
    try:
        resp = s.get(url, timeout=20)
        resp.raise_for_status()
        logger.info("Fetched history clients")
        return resp.json()
    except Exception as e:
        logger.error(f"Error fetching history clients - {e}")
        return []


def build_mac_name_map():
    active = get_active_clients()
    history = get_history_clients()

    try:
        active_len = len(active)
    except Exception:
        active_len = 0
    try:
        history_len = len(history)
    except Exception:
        history_len = 0

    logger.info(f"Active clients: {active_len}, History clients: {history_len}")

    mac_map = {}

    def best_name(c):
        return (
            c.get("display_name")
            or c.get("name")
            or c.get("hostname")
            or c.get("dev_name")
            or c.get("mac")
        )

    for c in active or []:
        mac = c.get("mac", "").lower()
        if not mac:
            continue
        mac_map[mac] = {"name": best_name(c), "ip": c.get("last_ip") or c.get("ip")}

    for c in history or []:
        mac = c.get("mac", "").lower()
        if not mac or mac in mac_map:
            continue
        mac_map[mac] = {"name": best_name(c), "ip": c.get("last_ip") or c.get("ip")}

    logger.info(f"MAC name map built - {len(mac_map)} entries")
    return mac_map
