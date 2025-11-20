# app/main.py
import logging
from logging.handlers import RotatingFileHandler
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.services.unifi_auth import ensure_logged_in, get_current_user
from app.services.unifi_service import get_traffic_rules, get_rule_by_id, build_mac_name_map
from app.routers import firewall

# ------------------------
# Logging Setup
# ------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[handler, logging.StreamHandler()])
logger = logging.getLogger("main")

logger.info("Starting UniFi Firewall Toggle App")

# ------------------------
# FastAPI App Setup
# ------------------------
app = FastAPI(title="UniFi Firewall Toggle")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
app.include_router(firewall.router)

# ------------------------
# Home / Dashboard
# ------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    logger.info("Home page accessed")

    # Lazy login: ensure we have a valid session before fetching data
    if not ensure_logged_in():
        logger.error("UniFi login failed - cannot continue")
        raise HTTPException(status_code=401, detail="Unable to login to UniFi API")

    traffic_rules = get_traffic_rules()
    logger.info(f"Fetched {len(traffic_rules) if isinstance(traffic_rules, list) else 0} traffic rules")

    # Safe counts
    try:
        data_list = traffic_rules if isinstance(traffic_rules, list) else traffic_rules.get("data", [])
        total_rules = len(data_list)
        allowed_rules = len([r for r in data_list if (r.get("action") or "").upper() == "ALLOW"])
        blocked_rules = total_rules - allowed_rules
    except Exception:
        total_rules = allowed_rules = blocked_rules = 0
        data_list = []

    return templates.TemplateResponse("index.html", {
        "request": request,
        "traffic_rules": data_list,
        "total_rules": total_rules,
        "allowed_rules": allowed_rules,
        "blocked_rules": blocked_rules,
        "user": get_current_user()
    })


# ------------------------
# Rule Detail Page
# ------------------------
@app.get("/rule/{rule_id}", response_class=HTMLResponse)
def rule_detail(request: Request, rule_id: str):
    logger.info(f"Rule detail requested - {rule_id}")

    if not ensure_logged_in():
        logger.error("UniFi login failed - cannot continue")
        raise HTTPException(status_code=401, detail="Unable to login to UniFi API")

    rule = get_rule_by_id(rule_id)
    if not rule:
        logger.error(f"Rule not found - {rule_id}")
        return HTMLResponse("Rule not found", status_code=404)

    client_map = build_mac_name_map()
    logger.info(f"Loaded MAC name map with {len(client_map)} clients")

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

    rule["target_devices"] = detailed_devices
    logger.info(f"Prepared rule detail for rule {rule_id}")

    return templates.TemplateResponse("rule_detail.html", {
        "request": request,
        "rule": rule
    })
