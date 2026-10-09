import os
from datetime import datetime

import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ================= PAGE CONFIG =================
st.set_page_config(
    page_title="DPI Security Dashboard",
    page_icon="🔐",
    layout="wide"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH = os.path.join(BASE_DIR, "traffic.csv")
API_URL = "http://127.0.0.1:8000"

# ================= THEME =================
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #050b14, #0a1220, #0d1726);
    color: #e6edf3;
}
[data-testid="stSidebar"] {
    background: #050a12;
}
h1, h2, h3 {
    color: #e2e8f0 !important;
}
[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 12px;
    padding: 16px;
}
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=5000, key="dpi_refresh")

# ================= HEADER =================
st.title("🔐 Deep Packet Inspection Dashboard")
st.caption("Network Traffic Analysis & Security Monitoring")
st.success("🟢 Dashboard refreshes every 5 seconds")
st.caption(f"Last refresh: {datetime.now():%d-%m-%Y %H:%M:%S}")

# ================= LOAD CSV =================
REQUIRED_COLUMNS = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "application", "domain", "packets", "bytes", "blocked"
]

df = pd.DataFrame()

try:
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError

    df = pd.read_csv(CSV_PATH)

    if df.empty and len(df.columns) == 0:
        raise pd.errors.EmptyDataError("CSV is empty")

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        st.error("CSV is missing columns: " + ", ".join(missing))
        st.stop()

except FileNotFoundError:
    st.warning("traffic.csv not found. Run the DPI engine first.")
    st.stop()

except pd.errors.EmptyDataError:
    st.warning("traffic.csv is empty. Run the DPI engine to generate traffic data.")
    st.stop()

except (OSError, pd.errors.ParserError) as error:
    st.error(f"Could not read traffic.csv: {error}")
    st.stop()

st.success("Traffic data loaded successfully!")

# Clean and normalize data
for col in ["src_ip", "dst_ip", "protocol", "application", "domain", "blocked"]:
    df[col] = df[col].fillna("").astype(str)

for col in ["src_port", "dst_port", "packets", "bytes"]:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

df["blocked"] = (
    df["blocked"].str.strip().str.lower()
    .map({"yes": "Yes", "no": "No"})
    .fillna("No")
)

# ================= SEARCH AND FILTERS =================
search = st.text_input(
    "🔎 Search IP, Domain or Application",
    placeholder="Example: YouTube, github.com, 192.168.1.50"
)

col1, col2, col3 = st.columns(3)

with col1:
    protocols = ["All"] + sorted(df["protocol"].unique().tolist())
    protocol_filter = st.selectbox("🔌 Protocol", protocols)

with col2:
    applications = ["All"] + sorted(df["application"].unique().tolist())
    app_filter = st.selectbox("📱 Application", applications)

with col3:
    blocked_filter = st.selectbox(
        "🚨 Traffic Status", ["All", "Allowed", "Blocked"]
    )

filtered_df = df.copy()

if protocol_filter != "All":
    filtered_df = filtered_df[filtered_df["protocol"] == protocol_filter]

if app_filter != "All":
    filtered_df = filtered_df[filtered_df["application"] == app_filter]

if blocked_filter == "Blocked":
    filtered_df = filtered_df[filtered_df["blocked"] == "Yes"]
elif blocked_filter == "Allowed":
    filtered_df = filtered_df[filtered_df["blocked"] == "No"]

if search.strip():
    query = search.strip().lower()
    searchable = ["src_ip", "dst_ip", "domain", "application", "protocol"]
    mask = pd.Series(False, index=filtered_df.index)

    for col in searchable:
        mask |= filtered_df[col].str.lower().str.contains(
            query, na=False, regex=False
        )

    filtered_df = filtered_df[mask]

# ================= TRAFFIC OVERVIEW =================
st.subheader("📊 Traffic Overview")

c1, c2, c3, c4 = st.columns(4)

blocked_count = int((filtered_df["blocked"] == "Yes").sum())

c1.metric("Active Flows", len(filtered_df))
c2.metric("Applications", filtered_df["application"].nunique())
c3.metric("Source IPs", filtered_df["src_ip"].nunique())
c4.metric("Blocked Flows", blocked_count)

# ================= NETWORK STATISTICS =================
st.subheader("📈 Network Statistics")

c1, c2, c3, c4 = st.columns(4)

total_packets = int(filtered_df["packets"].sum())
total_bytes = int(filtered_df["bytes"].sum())
allowed_count = int((filtered_df["blocked"] == "No").sum())
unique_domains = filtered_df["domain"].replace("", pd.NA).dropna().nunique()

c1.metric("Total Packets", f"{total_packets:,}")
c2.metric("Total Bytes", f"{total_bytes:,}")
c3.metric("Allowed Flows", allowed_count)
c4.metric("Detected Domains", unique_domains)

# ================= SECURITY STATUS =================
st.subheader("🛡️ Security Status")

if blocked_count:
    st.warning(f"🚨 {blocked_count} blocked flow(s) detected!")
else:
    st.success("✅ No blocked traffic detected")

# ================= CHARTS =================
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("📱 Application Distribution")
    app_counts = filtered_df["application"].replace("", "Unknown").value_counts()

    if not app_counts.empty:
        st.bar_chart(app_counts)
    else:
        st.info("No application data available.")

with chart2:
    st.subheader("🔌 Protocol Distribution")
    protocol_counts = filtered_df["protocol"].replace("", "Unknown").value_counts()

    if not protocol_counts.empty:
        st.bar_chart(protocol_counts)
    else:
        st.info("No protocol data available.")

# ================= TOP DOMAINS =================
st.subheader("🌐 Top Detected Domains")

domain_data = (
    filtered_df.loc[filtered_df["domain"] != "", "domain"]
    .value_counts()
    .head(10)
)

if not domain_data.empty:
    st.bar_chart(domain_data)
else:
    st.info("No domains detected in current traffic.")

# ================= TOP APPLICATIONS =================
st.subheader("🏆 Top Applications")

top_apps = (
    filtered_df["application"]
    .replace("", "Unknown")
    .value_counts()
    .head(10)
)

if not top_apps.empty:
    apps_table = top_apps.rename("Flows").reset_index()
    apps_table.columns = ["Application", "Flows"]
    st.dataframe(apps_table, use_container_width=True, hide_index=True)

# ================= BLOCKED TRAFFIC =================
st.subheader("🚨 Blocked Traffic")

blocked_df = filtered_df[filtered_df["blocked"] == "Yes"]

if not blocked_df.empty:
    st.dataframe(blocked_df, use_container_width=True, hide_index=True)
else:
    st.success("No blocked traffic currently detected.")

# ================= ALL TRAFFIC =================
st.subheader("📋 Network Traffic")
st.dataframe(filtered_df, use_container_width=True, hide_index=True)

# ================= SECURITY RULES =================
st.divider()
st.header("🛡️ Security Rules")

try:
    response = requests.get(f"{API_URL}/rules", timeout=3)

    if response.ok:
        rules = response.json().get("rules", [])
    else:
        rules = []
        st.warning(f"Backend returned HTTP {response.status_code}.")

except requests.RequestException:
    rules = []
    st.info("FastAPI is not running. Start the backend to manage rules.")

# ================= ADD RULE =================
st.subheader("➕ Add Security Rule")

r1, r2, r3 = st.columns(3)

with r1:
    rule_type = st.selectbox(
        "Rule Type", ["IP", "DOMAIN", "APPLICATION", "PORT"]
    )

with r2:
    rule_value = st.text_input(
        "Rule Value", placeholder="Example: 192.168.1.50"
    )

with r3:
    st.write("")
    st.write("")
    add_rule = st.button("🚫 Block", use_container_width=True)

if add_rule:
    if not rule_value.strip():
        st.error("Please enter a rule value.")
    else:
        try:
            response = requests.post(
                f"{API_URL}/rules",
                json={"type": rule_type, "value": rule_value.strip()},
                timeout=5
            )

            if response.ok:
                st.success("Security rule added successfully!")
                st.rerun()
            else:
                st.error(f"Failed to add rule: {response.text}")

        except requests.RequestException:
            st.error("Cannot connect to FastAPI. Start the backend first.")

# ================= EXISTING RULES =================
st.subheader("📋 Active Security Rules")

if rules:
    for rule in rules:
        rule_id = rule.get("id")
        current_type = rule.get("type", "UNKNOWN")
        current_value = rule.get("value", "")
        status = rule.get("status", "Active")

        c