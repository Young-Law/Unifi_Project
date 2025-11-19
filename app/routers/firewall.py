from fastapi import APIRouter, HTTPException
from app.services.unifi_service import get_traffic_rules, update_traffic_rule

router = APIRouter(prefix="/api/firewall", tags=["Firewall"])

@router.post("/toggle_rule/{rule_id}")
def toggle_traffic_rule(rule_id: str):
    """Toggle a UniFi traffic rule between ALLOW and BLOCK."""
    try:
        # Step 1: Get all rules
        rules = get_traffic_rules()
        if not isinstance(rules, list):
            raise ValueError("Unexpected response format")

        # Step 2: Find the rule
        rule = next((r for r in rules if r.get("_id") == rule_id), None)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")

        # Step 3: Flip the action
        if rule["action"].upper() == "ALLOW":
            rule["action"] = "BLOCK"
        else:
            rule["action"] = "ALLOW"

        # Step 4: Push update to UniFi
        result = update_traffic_rule(rule_id, rule)

        return {"success": True, "rule": result}
    except Exception as e:
        print("Toggle error:", e)
        raise HTTPException(status_code=500, detail=str(e))
