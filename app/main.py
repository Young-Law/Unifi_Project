import logging
from logging.handlers import RotatingFileHandler
import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from app.services.unifi_session import check_any_session_valid
from app.services.unifi_service import get_traffic_rules, get_rule_by_id, build_mac_name_map
from app.routers import firewall, auth

# ------------------------
# Logging Setup
# ------------------------

# Build log file path relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Ensure logs folder exists
os.makedirs(LOG_DIR, exist_ok=True)

# FIX: Removed Unicode arrow "→" because Windows console cannot display it
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"

handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[handler, logging.StreamHandler()]
)
logger = logging.getLogger("main")

logger.info("Starting UniFi Firewall Toggle App")

app = FastAPI(title="UniFi Firewall Toggle")

# Serve static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include routers
app.include_router(firewall.router)
app.include_router(auth.router)


# ------------------------
# Home / Dashboard
# ------------------------
@app.get("/")
def home(request: Request):
    logger.info("Home page accessed")

    session_status = check_any_session_valid()
    if not session_status["ok"]:
        logger.warning("Session invalid - session_expired.html")
        return templates.TemplateResponse("session_expired.html", {"request": request})

    traffic_rules = get_traffic_rules()
    logger.info(f"Fetched {len(traffic_rules)} traffic rules")

    total_rules = len(traffic_rules)
    allowed_rules = len([r for r in traffic_rules if r.get("action") == "ALLOW"])
    blocked_rules = len([r for r in traffic_rules if r.get("action") == "BLOCK"])

    return templates.TemplateResponse("index.html", {
        "request": request,
        "traffic_rules": traffic_rules,
        "total_rules": total_rules,
        "allowed_rules": allowed_rules,
        "blocked_rules": blocked_rules,
        "user": session_status.get("user")
    })


# ------------------------
# Rule Detail Page
# ------------------------
@app.get("/rule/{rule_id}", response_class=HTMLResponse)
def rule_detail(request: Request, rule_id: str):
    logger.info(f"Rule detail requested - {rule_id}")

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
