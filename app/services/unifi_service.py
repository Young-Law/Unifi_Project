# app/services/unifi_service.py
import logging
import os
import requests
from typing import Optional, List, Dict, Any
from app.services.unifi_auth import get_session, ensure_logged_in, get_current_user
import json
import base64


logger = logging.getLogger("unifi_service")
logger.setLevel(logging.DEBUG)


UNIFI_HOST = os.getenv("UNIFI_HOST", "https://192.168.10.1")
BASE_URL = f"{UNIFI_HOST}/proxy/network/v2/api/site/default"
FIREWALL_POLICIES_PATH = "firewall-policies"
CLIENTS_ACTIVE_PATH = "clients/active?includeTrafficUsage=true&includeUnifiDevices=true"
CLIENTS_HISTORY_PATH = "clients/history?includeUnifiDevices=true&onlyNonBlocked=false&withinHours=87600"


def _get_session_or_warn():
    s = get_session()
    if not s:
        logger.warning("No valid UniFi session (get_session returned None)")
    return s


def _fetch_raw_firewall_policies() -> list:
    """Fetch all raw firewall policies from the UniFi API."""
    s = _get_session_or_warn()
    if not s:
        return []

    url = f"{BASE_URL}/{FIREWALL_POLICIES_PATH}"
    try:
        resp = s.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("data", [])
    except Exception as e:
        logger.error(f"Error fetching firewall policies: {e}")
        return []


def _group_firewall_policies(policies: list) -> list:
    """
    Filter custom firewall policies (predefined is False and protocol is 'all')
    and group them by policy name (e.g., across multiple network zones).
    """
    filtered = [
        p for p in policies
        if not p.get("predefined", False) and p.get("protocol") == "all"
    ]

    groups: Dict[str, Dict[str, Any]] = {}
    for p in filtered:
        name = p.get("name", "Unnamed Rule")
        policy_id = p.get("_id")
        action = (p.get("action") or "ALLOW").upper()

        source = p.get("source") or {}
        macs = source.get("client_macs") or []

        if name not in groups:
            groups[name] = {
                "_id": policy_id,
                "name": name,
                "description": name,
                "action": action,
                "enabled": p.get("enabled", True),
                "policy_ids": [policy_id],
                "target_devices": list(macs),
                "matching_target": source.get("matching_target", "CLIENT"),
                "raw_policies": [p],
            }
        else:
            groups[name]["policy_ids"].append(policy_id)
            groups[name]["raw_policies"].append(p)
            for mac in macs:
                if mac not in groups[name]["target_devices"]:
                    groups[name]["target_devices"].append(mac)
            if action == "BLOCK":
                groups[name]["action"] = "BLOCK"

    return list(groups.values())


def get_traffic_rules() -> list:
    """
    Get custom firewall rules grouped by name.
    Preserves the previous interface for routers and templates.
    """
    raw_policies = _fetch_raw_firewall_policies()
    grouped = _group_firewall_policies(raw_policies)
    logger.info(f"Fetched and grouped {len(grouped)} firewall rules successfully")
    return grouped


def get_rule_by_id(rule_id: str) -> Optional[dict]:
    """Find a grouped rule by its primary _id or any member policy _id."""
    rules = get_traffic_rules()
    for rule in rules:
        if rule.get("_id") == rule_id or rule_id in rule.get("policy_ids", []):
            return rule
    logger.warning(f"Rule not found - {rule_id}")
    return None


def _get_csrf_headers(s: requests.Session) -> Optional[dict]:
    """Extract CSRF token from the session JWT cookie and build required headers."""
    token = s.cookies.get("TOKEN")
    if not token:
        logger.error("No TOKEN cookie found in session. Cannot update rule.")
        return None

    csrf_token = token
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = base64.b64decode(payload)
            jwt_data = json.loads(decoded)
            csrf_token = jwt_data.get("csrfToken", token)
    except Exception:
        pass

    return {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "x-csrf-token": csrf_token,
        "origin": UNIFI_HOST,
        "referer": f"{UNIFI_HOST}/",
    }


def update_traffic_rule(rule_id: str, new_action: str):
    """
    Update a UniFi firewall policy group ('ALLOW' or 'BLOCK') by sending PUT
    to each underlying individual firewall policy endpoint.
    """
    s = get_session()
    if not s:
        logger.warning("No valid UniFi session available.")
        return None

    group_rule = get_rule_by_id(rule_id)
    if not group_rule:
        logger.error(f"Rule {rule_id} not found")
        return None

    headers = _get_csrf_headers(s)
    if not headers:
        return None

    action_upper = new_action.upper()
    policy_ids = group_rule.get("policy_ids", [rule_id])
    raw_policies = _fetch_raw_firewall_policies()
    raw_map = {p.get("_id"): p for p in raw_policies if p.get("_id")}

    updated_count = 0
    for pid in policy_ids:
        policy = raw_map.get(pid)
        if not policy:
            logger.warning(f"Underlying policy {pid} not found in raw policies")
            continue

        policy["action"] = action_upper
        url_put = f"{BASE_URL}/{FIREWALL_POLICIES_PATH}/{pid}"
        try:
            put_resp = s.put(url_put, json=policy, headers=headers, timeout=10, verify=False)
            put_resp.raise_for_status()
            updated_count += 1
        except Exception as e:
            logger.error(f"Failed to update policy {pid}: {e}")

    if updated_count == 0:
        logger.error(f"Failed to update any policies for group {rule_id}")
        return None

    logger.info(f"Group {group_rule.get('name')} ({updated_count} policies) updated to {action_upper}")
    group_rule["action"] = action_upper
    return group_rule


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


def resolve_rule_devices(rule: dict) -> list:
    """
    Given a rule dict containing 'target_devices' (MAC addresses or device dicts),
    resolve each device against active and history client maps.
    Returns a list of dicts with 'name', 'ip', and 'mac'.
    """
    client_map = build_mac_name_map()
    logger.info(f"Loaded MAC name map with {len(client_map)} clients for rule device resolution")

    detailed_devices = []
    for device in rule.get("target_devices", []):
        if isinstance(device, dict):
            mac = device.get("client_mac") or device.get("mac") or str(device)
        else:
            mac = str(device)

        mac_lower = mac.lower()
        client_info = client_map.get(mac_lower, {})

        detailed_devices.append({
            "name": client_info.get("name", mac),
            "ip": client_info.get("ip"),
            "mac": mac_lower
        })

    return detailed_devices

