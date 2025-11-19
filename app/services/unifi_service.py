import logging
import os
import requests
from app.services.unifi_session import get_active_session_auth

# ------------------------------
# Ensure logs folder exists
# ------------------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Standard logger
logger = logging.getLogger("unifi_service")

BASE_URL = "https://192.168.10.1/proxy/network/v2/api/site/default"


def get_traffic_rules():
    headers, cookies = get_active_session_auth()

    if not cookies:
        logger.warning("No valid UniFi session for get_traffic_rules")
        return []

    try:
        response = requests.get(
            f"{BASE_URL}/trafficrules",
            headers=headers,
            cookies=cookies,
            verify=False
        )
        response.raise_for_status()
        logger.info("Fetched traffic rules successfully")
        return response.json()

    except Exception as e:
        logger.error(f"Error fetching traffic rules - {e}")
        return []


def update_traffic_rule(rule_id, updated_rule):
    headers, cookies = get_active_session_auth()

    if not cookies:
        logger.warning("No valid UniFi session for update_traffic_rule")
        return None

    url = f"{BASE_URL}/trafficrules/{rule_id}"

    # Extract ALLOW/BLOCK for logging
    new_action = updated_rule.get("action", "").upper() or "UNKNOWN"

    try:
        response = requests.put(
            url,
            headers=headers,
            cookies=cookies,
            json=updated_rule,
            verify=False
        )
        response.raise_for_status()

        logger.info(
            f"Rule updated successfully - {rule_id} - Action changed to: {new_action}"
        )

        return response.json()

    except Exception as e:
        logger.error(f"Error updating traffic rule {rule_id} - {e}")
        return None


def get_rule_by_id(rule_id: str):
    rules = get_traffic_rules()
    for rule in rules:
        if rule.get("_id") == rule_id:
            return rule
    logger.warning(f"Rule not found - {rule_id}")
    return None


def get_active_clients():
    headers, cookies = get_active_session_auth()
    if not cookies:
        logger.warning("No session for get_active_clients")
        return []

    try:
        res = requests.get(
            f"{BASE_URL}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true",
            headers=headers,
            cookies=cookies,
            verify=False
        )
        res.raise_for_status()
        logger.info("Fetched active clients")
        return res.json()
    except Exception as e:
        logger.error(f"Error fetching active clients - {e}")
        return []


def get_history_clients():
    headers, cookies = get_active_session_auth()
    if not cookies:
        logger.warning("No session for get_history_clients")
        return []

    try:
        res = requests.get(
            f"{BASE_URL}/clients/history?includeUnifiDevices=true&onlyNonBlocked=false&withinHours=87600",
            headers=headers,
            cookies=cookies,
            verify=False
        )
        res.raise_for_status()
        logger.info("Fetched history clients")
        return res.json()

    except Exception as e:
        logger.error(f"Error fetching history clients - {e}")
        return []


def build_mac_name_map():
    active = get_active_clients()
    history = get_history_clients()

    logger.info(f"Active clients: {len(active)}, History clients: {len(history)}")

    mac_map = {}

    def best_name(c):
        return (
            c.get("display_name")
            or c.get("name")
            or c.get("hostname")
            or c.get("dev_name")
            or c.get("mac")
        )

    for c in active:
        mac = c.get("mac", "").lower()
        if not mac:
            continue
        mac_map[mac] = {"name": best_name(c), "ip": c.get("last_ip") or c.get("ip")}

    for c in history:
        mac = c.get("mac", "").lower()
        if not mac or mac in mac_map:
            continue
        mac_map[mac] = {"name": best_name(c), "ip": c.get("last_ip") or c.get("ip")}

    logger.info(f"MAC name map built - {len(mac_map)} entries")
    return mac_map
