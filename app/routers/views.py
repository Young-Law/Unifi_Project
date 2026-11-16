# app/routers/views.py
import logging
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates

from app.services.unifi_auth import ensure_logged_in, get_current_user
from app.services.unifi_service import (
    get_traffic_rules,
    get_rule_by_id,
    resolve_rule_devices,
)

logger = logging.getLogger("views")

router = APIRouter(tags=["Views"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Serve the tab/address bar favicon directly."""
    return FileResponse("app/static/icon.png")


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Render the dashboard listing all custom firewall rules and access statuses."""
    logger.info("Home page accessed")

    if not ensure_logged_in():
        logger.error("UniFi login failed - cannot continue")
        raise HTTPException(status_code=401, detail="Unable to login to UniFi API")

    traffic_rules = get_traffic_rules()
    data_list = traffic_rules if isinstance(traffic_rules, list) else traffic_rules.get("data", [])
    total_rules = len(data_list)
    allowed_rules = len([r for r in data_list if (r.get("action") or "").upper() == "ALLOW"])
    blocked_rules = total_rules - allowed_rules

    return templates.TemplateResponse("index.html", {
        "request": request,
        "traffic_rules": data_list,
        "total_rules": total_rules,
        "allowed_rules": allowed_rules,
        "blocked_rules": blocked_rules,
        "user": get_current_user(),
    })


@router.get("/rule/{rule_id}", response_class=HTMLResponse)
def rule_detail(request: Request, rule_id: str):
    """Render the detail page for a specific rule and its connected devices."""
    logger.info(f"Rule detail requested - {rule_id}")

    if not ensure_logged_in():
        logger.error("UniFi login failed - cannot continue")
        raise HTTPException(status_code=401, detail="Unable to login to UniFi API")

    rule = get_rule_by_id(rule_id)
    if not rule:
        logger.error(f"Rule not found - {rule_id}")
        return HTMLResponse("Rule not found", status_code=404)

    # Resolve connected client details via service helper
    rule_copy = dict(rule)
    rule_copy["target_devices"] = resolve_rule_devices(rule_copy)

    return templates.TemplateResponse("rule_detail.html", {
        "request": request,
        "rule": rule_copy,
    })
