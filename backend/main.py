from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import os
import json


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="DPI Security API",
    description="Backend API for Deep Packet Inspection Dashboard",
    version="1.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# FILE LOCATIONS
# =========================================================

PROJECT_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        ".."
    )
)

CSV_FILE = os.path.join(
    PROJECT_DIR,
    "traffic.csv"
)

RULES_FILE = os.path.join(
    PROJECT_DIR,
    "rules.json"
)


# =========================================================
# HELPER FUNCTION - LOAD TRAFFIC
# =========================================================

def load_traffic():

    if not os.path.exists(CSV_FILE):
        return pd.DataFrame()

    try:
        return pd.read_csv(CSV_FILE)

    except Exception:
        return pd.DataFrame()


# =========================================================
# HELPER FUNCTION - LOAD RULES
# =========================================================

def load_rules():

    if not os.path.exists(RULES_FILE):
        return []

    try:

        with open(
            RULES_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except Exception:

        return []


# =========================================================
# HELPER FUNCTION - SAVE RULES
# =========================================================

def save_rules(rules):

    with open(
        RULES_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            rules,
            file,
            indent=4
        )


# =========================================================
# ROOT API
# =========================================================

@app.get("/")
def root():

    return {
        "status": "online",
        "service": "DPI Security API",
        "version": "1.0"
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# =========================================================
# ALL TRAFFIC
# =========================================================

@app.get("/traffic")
def get_traffic():

    df = load_traffic()

    if df.empty:

        return {
            "count": 0,
            "traffic": []
        }

    df = df.fillna("")

    return {
        "count": len(df),
        "traffic": df.to_dict(
            orient="records"
        )
    }


# =========================================================
# STATISTICS
# =========================================================

@app.get("/stats")
def get_stats():

    df = load_traffic()

    if df.empty:

        return {
            "active_flows": 0,
            "applications": 0,
            "source_ips": 0,
            "blocked_flows": 0,
            "total_packets": 0,
            "total_bytes": 0,
            "detected_domains": 0
        }

    blocked = (
        df["blocked"]
        .astype(str)
        .str.lower()
        == "yes"
    ).sum()

    domains = (
        df["domain"]
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )

    return {
        "active_flows": len(df),

        "applications": int(
            df["application"].nunique()
        ),

        "source_ips": int(
            df["src_ip"].nunique()
        ),

        "blocked_flows": int(
            blocked
        ),

        "total_packets": int(
            df["packets"].sum()
        ),

        "total_bytes": int(
            df["bytes"].sum()
        ),

        "detected_domains": int(
            domains
        )
    }


# =========================================================
# APPLICATION DISTRIBUTION
# =========================================================

@app.get("/applications")
def get_applications():

    df = load_traffic()

    if df.empty:
        return []

    result = (
        df["application"]
        .value_counts()
        .reset_index()
    )

    result.columns = [
        "application",
        "flows"
    ]

    return result.to_dict(
        orient="records"
    )


# =========================================================
# PROTOCOL DISTRIBUTION
# =========================================================

@app.get("/protocols")
def get_protocols():

    df = load_traffic()

    if df.empty:
        return []

    result = (
        df["protocol"]
        .value_counts()
        .reset_index()
    )

    result.columns = [
        "protocol",
        "flows"
    ]

    return result.to_dict(
        orient="records"
    )


# =========================================================
# DOMAINS
# =========================================================

@app.get("/domains")
def get_domains():

    df = load_traffic()

    if df.empty:
        return []

    result = (
        df[
            df["domain"].notna()
            & (df["domain"] != "")
        ]["domain"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    result.columns = [
        "domain",
        "flows"
    ]

    return result.to_dict(
        orient="records"
    )


# =========================================================
# BLOCKED TRAFFIC
# =========================================================

@app.get("/blocked")
def get_blocked():

    df = load_traffic()

    if df.empty:
        return []

    blocked_df = df[
        df["blocked"]
        .astype(str)
        .str.lower()
        == "yes"
    ]

    blocked_df = blocked_df.fillna("")

    return blocked_df.to_dict(
        orient="records"
    )


# =========================================================
# SECURITY RULES
# =========================================================

@app.get("/rules")
def get_rules():

    rules = load_rules()

    return {
        "count": len(rules),
        "rules": rules
    }


# =========================================================
# ADD SECURITY RULE
# =========================================================

@app.post("/rules")
def add_rule(rule: dict):

    rule_type = str(
        rule.get("type", "")
    ).upper().strip()

    value = str(
        rule.get("value", "")
    ).strip()

    if not rule_type:
        raise HTTPException(
            status_code=400,
            detail="Rule type is required"
        )

    if not value:
        raise HTTPException(
            status_code=400,
            detail="Rule value is required"
        )

    allowed_types = [
        "IP",
        "DOMAIN",
        "APPLICATION",
        "PORT"
    ]

    if rule_type not in allowed_types:

        raise HTTPException(
            status_code=400,
            detail="Invalid rule type"
        )

    rules = load_rules()

    new_id = 1

    if rules:

        ids = [
            r.get("id", 0)
            for r in rules
            if isinstance(r.get("id", 0), int)
        ]

        if ids:
            new_id = max(ids) + 1

    new_rule = {
        "id": new_id,
        "type": rule_type,
        "value": value,
        "action": "BLOCK",
        "status": "Active"
    }

    rules.append(new_rule)

    save_rules(rules)

    return {
        "success": True,
        "rule": new_rule
    }


# =========================================================
# DELETE SECURITY RULE
# =========================================================

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: int):

    rules = load_rules()

    updated_rules = [
        rule
        for rule in rules
        if rule.get("id") != rule_id
    ]

    if len(updated_rules) == len(rules):

        raise HTTPException(
            status_code=404,
            detail="Rule not found"
        )

    save_rules(updated_rules)

    return {
        "success": True,
        "message": "Rule deleted"
    }


# =========================================================
# ENABLE / DISABLE SECURITY RULE
# =========================================================

@app.put("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: int):

    rules = load_rules()

    found = False

    for rule in rules:

        if rule.get("id") == rule_id:

            found = True

            if rule.get("status") == "Active":

                rule["status"] = "Disabled"

            else:

                rule["status"] = "Active"

            break

    if not found:

        raise HTTPException(
            status_code=404,
            detail="Rule not found"
        )

    save_rules(rules)

    return {
        "success": True,
        "rules": rules
    }