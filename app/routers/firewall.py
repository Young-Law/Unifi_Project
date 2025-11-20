# app/routers/firewall.py
from fastapi import APIRouter, HTTPException
from app.services.unifi_service import get_traffic_rules, get_rule_by_id, update_traffic_rule

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])


@router.post("/toggle_rule/{rule_id}")
def toggle_traffic_rule(rule_id: str):
    """Toggle a UniFi traffic rule between ALLOW and BLOCK."""
    try:
        rule = get_rule_by_id(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        current_action = (rule.get("action") or "").upper()
        new_action = "BLOCK" if current_action == "ALLOW" else "ALLOW"

        success = update_traffic_rule(rule_id, new_action)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update rule")

        return {"success": True, "rule_id": rule_id, "new_action": new_action}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
