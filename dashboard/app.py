import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from datetime import datetime


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="DPI Security Dashboard",
    page_icon="🔐",
    layout="wide"
)


# =========================================================
# CUSTOM CYBERSECURITY THEME
# =========================================================

st.markdown("""
<style>

/* Main application background */
.stApp {
    background:
        radial-gradient(
            circle at top right,
            rgba(0, 90, 150, 0.18),
            transparent 35%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(0, 160, 120, 0.10),
            transparent 35%
        ),
        linear-gradient(
            135deg,
            #050b14 0%,
            #0a1220 50%,
            #0d1726 100%
        );

    color: #e6edf3;
}


/* Sidebar */
[data-testid="stSidebar"] {
    background:
        linear-gradient(
            180deg,
            #050a12 0%,
            #08111d 100%
        );

    border-right: 1px solid rgba(255,255,255,0.08);
}


/* Sidebar text */
[data-testid="stSidebar"] * {
    color: #dbe7f3;
}


/* Main title */
h1 {
    color: #f1f5f9 !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px;
}


/* Section headings */
h2, h3 {
    color: #e2e8f0 !important;
}


/* Captions */
.stCaption {
    color: #94a3b8 !important;
}


/* Metric cards */
[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.72);

    border: 1px solid rgba(
        148,
        163,
        184,
        0.14
    );

    border-radius: 14px;

    padding: 18px;

    box-shadow:
        0 8px 25px rgba(0,0,0,0.18);
}


/* Metric labels */
[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
}


/* Metric values */
[data-testid="stMetricValue"] {
    color: #f8fafc !important;
}


/* Select boxes */
div[data-baseweb="select"] > div {
    background-color:
        rgba(15, 23, 42, 0.85);

    border-color:
        rgba(148, 163, 184, 0.20);

    border-radius: 10px;
}


/* Text input */
div[data-baseweb="input"] {
    background-color:
        rgba(15, 23, 42, 0.85);

    border-radius: 10px;
}


/* Text input text */
div[data-baseweb="input"] input {
    color: #f8fafc !important;
}


/* Dataframes */
[data-testid="stDataFrame"] {
    border:
        1px solid rgba(
            148,
            163,
            184,
            0.12
        );

    border-radius: 12px;

    overflow: hidden;
}


/* Alerts */
div[data-testid="stAlert"] {
    border-radius: 10px;
}


/* Buttons */
.stButton > button {
    border-radius: 9px;

    border:
        1px solid rgba(
            148,
            163,
            184,
            0.20
        );

    background:
        rgba(15, 23, 42, 0.8);

    color: #e2e8f0;
}


/* Button hover */
.stButton > button:hover {
    border-color:
        rgba(59, 130, 246, 0.7);

    color: #ffffff;
}


/* Divider */
hr {
    border-color:
        rgba(148, 163, 184, 0.12);
}


/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}


/* Hide Streamlit footer */
footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# AUTO REFRESH
# =========================================================

st_autorefresh(
    interval=5000,
    key="dpi_refresh"
)


# =========================================================
# HEADER
# =========================================================

st.title(
    "🔐 Deep Packet Inspection Dashboard"
)

st.caption(
    "Network Traffic Analysis & Security Monitoring"
)

st.success(
    "🟢 LIVE MONITORING ACTIVE — "
    "Dashboard refreshes every 5 seconds"
)

st.caption(
    f"Last refresh: "
    f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
)


# =========================================================
# LOAD TRAFFIC DATA
# =========================================================

try:

    df = pd.read_csv("traffic.csv")

    st.success(
        "Traffic data loaded successfully!"
    )


    # =====================================================
    # SEARCH
    # =====================================================

    search = st.text_input(
        "🔎 Search IP, Domain or Application",
        placeholder=(
            "Example: 192.168.1.34, "
            "YouTube, github.com"
        )
    )


    # =====================================================
    # FILTERS
    # =====================================================

    col1, col2, col3 = st.columns(3)


    # =====================================================
    # PROTOCOL FILTER
    # =====================================================

    with col1:

        protocols = ["All"] + sorted(
            df["protocol"]
            .dropna()
            .unique()
            .tolist()
        )

        protocol_filter = st.selectbox(
            "🔌 Protocol",
            protocols
        )


    # =====================================================
    # APPLICATION FILTER
    # =====================================================

    with col2:

        applications = ["All"] + sorted(
            df["application"]
            .dropna()
            .unique()
            .tolist()
        )

        app_filter = st.selectbox(
            "📱 Application",
            applications
        )


    # =====================================================
    # TRAFFIC STATUS FILTER
    # =====================================================

    with col3:

        blocked_filter = st.selectbox(
            "🚨 Traffic Status",
            [
                "All",
                "Allowed",
                "Blocked"
            ]
        )


    # =====================================================
    # APPLY FILTERS
    # =====================================================

    filtered_df = df.copy()


    # Protocol filter

    if protocol_filter != "All":

        filtered_df = filtered_df[
            filtered_df["protocol"]
            == protocol_filter
        ]


    # Application filter

    if app_filter != "All":

        filtered_df = filtered_df[
            filtered_df["application"]
            == app_filter
        ]


    # Traffic status filter

    if blocked_filter == "Blocked":

        filtered_df = filtered_df[
            filtered_df["blocked"]
            == "Yes"
        ]

    elif blocked_filter == "Allowed":

        filtered_df = filtered_df[
            filtered_df["blocked"]
            == "No"
        ]


    # Search filter

    if search:

        search_lower = search.lower()

        filtered_df = filtered_df[
            filtered_df.astype(str)
            .apply(
                lambda row:
                row.str.lower()
                .str.contains(
                    search_lower,
                    na=False
                )
                .any(),
                axis=1
            )
        ]


    # =====================================================
    # TRAFFIC OVERVIEW
    # =====================================================

    st.subheader(
        "📊 Traffic Overview"
    )

    col1, col2, col3, col4 = st.columns(4)


    # Active flows

    col1.metric(
        "Active Flows",
        len(filtered_df)
    )


    # Applications

    col2.metric(
        "Applications",
        filtered_df[
            "application"
        ].nunique()
    )


    # Source IPs

    col3.metric(
        "Source IPs",
        filtered_df[
            "src_ip"
        ].nunique()
    )


    # Blocked flows

    blocked_count = (
        filtered_df["blocked"]
        == "Yes"
    ).sum()

    col4.metric(
        "Blocked Flows",
        blocked_count
    )


    # =====================================================
    # NETWORK STATISTICS
    # =====================================================

    st.subheader(
        "📈 Network Statistics"
    )

    col1, col2, col3, col4 = st.columns(4)


    total_packets = (
        filtered_df["packets"].sum()
    )


    total_bytes = (
        filtered_df["bytes"].sum()
    )


    allowed_count = (
        filtered_df["blocked"]
        == "No"
    ).sum()


    unique_domains = (
        filtered_df["domain"]
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )


    col1.metric(
        "Total Packets",
        f"{total_packets:,}"
    )


    col2.metric(
        "Total Bytes",
        f"{total_bytes:,}"
    )


    col3.metric(
        "Allowed Flows",
        allowed_count
    )


    col4.metric(
        "Detected Domains",
        unique_domains
    )


    # =====================================================
    # SECURITY STATUS
    # =====================================================

    st.subheader(
        "🛡️ Security Status"
    )


    if blocked_count > 0:

        st.warning(
            f"🚨 {blocked_count} "
            f"blocked flow(s) detected!"
        )

    else:

        st.success(
            "✅ No blocked traffic detected"
        )


    # =====================================================
    # CHARTS
    # =====================================================

    chart1, chart2 = st.columns(2)


    # =====================================================
    # APPLICATION DISTRIBUTION
    # =====================================================

    with chart1:

        st.subheader(
            "📱 Application Distribution"
        )

        app_counts = (
            filtered_df["application"]
            .value_counts()
        )


        if not app_counts.empty:

            st.bar_chart(
                app_counts
            )

        else:

            st.info(
                "No application data available."
            )


    # =====================================================
    # PROTOCOL DISTRIBUTION
    # =====================================================

    with chart2:

        st.subheader(
            "🔌 Protocol Distribution"
        )

        protocol_counts = (
            filtered_df["protocol"]
            .value_counts()
        )


        if not protocol_counts.empty:

            st.bar_chart(
                protocol_counts
            )

        else:

            st.info(
                "No protocol data available."
            )


    # =====================================================
    # TOP DOMAINS
    # =====================================================

    st.subheader(
        "🌐 Top Detected Domains"
    )


    domain_data = (
        filtered_df[
            filtered_df["domain"].notna()
            &
            (
                filtered_df["domain"]
                != ""
            )
        ]["domain"]
        .value_counts()
        .head(10)
    )


    if not domain_data.empty:

        st.bar_chart(
            domain_data
        )

    else:

        st.info(
            "No domains detected "
            "in the current traffic."
        )


    # =====================================================
    # TOP APPLICATIONS
    # =====================================================

    st.subheader(
        "🏆 Top Applications"
    )


    top_apps = (
        filtered_df["application"]
        .value_counts()
        .head(10)
    )


    if not top_apps.empty:

        top_apps_table = (
            top_apps
            .rename("Flows")
            .reset_index()
        )


        top_apps_table.columns = [
            "Application",
            "Flows"
        ]


        st.dataframe(
            top_apps_table,
            use_container_width=True,
            hide_index=True
        )


    # =====================================================
    # BLOCKED TRAFFIC
    # =====================================================

    st.subheader(
        "🚨 Blocked Traffic"
    )


    blocked_df = filtered_df[
        filtered_df["blocked"]
        == "Yes"
    ]


    if not blocked_df.empty:

        st.dataframe(
            blocked_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No blocked traffic "
            "currently detected."
        )


    # =====================================================
    # NETWORK TRAFFIC TABLE
    # =====================================================

    st.subheader(
        "📋 Network Traffic"
    )


    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )


    # =====================================================
    # FOOTER
    # =====================================================

    st.divider()


    st.caption(
        "🔐 Deep Packet Inspection Engine • "
        "C++ DPI Core • Npcap/Wireshark Capture • "
        "Streamlit Security Dashboard"
    )


# =========================================================
# FILE NOT FOUND
# =========================================================

except FileNotFoundError:

    st.error(
        "❌ traffic.csv not found."
    )


    st.info(
        "Run the DPI engine first to generate "
        "traffic.csv."
    )
    # =========================================================
# SECURITY RULES
# =========================================================

st.divider()

st.header("🛡️ Security Rules")

API_URL = "http://127.0.0.1:8000"


# Load existing rules
try:
    response = requests.get(
        f"{API_URL}/rules",
        timeout=3
    )

    if response.status_code == 200:
        rules_data = response.json()
        rules = rules_data.get("rules", [])
    else:
        rules = []

except Exception:
    rules = []


# =========================================================
# ADD NEW RULE
# =========================================================

st.subheader("➕ Add Security Rule")

rule_col1, rule_col2, rule_col3 = st.columns(3)

with rule_col1:

    rule_type = st.selectbox(
        "Rule Type",
        [
            "IP",
            "DOMAIN",
            "APPLICATION",
            "PORT"
        ]
    )


with rule_col2:

    rule_value = st.text_input(
        "Rule Value",
        placeholder="Example: 192.168.1.50"
    )


with rule_col3:

    st.write("")
    st.write("")

    add_rule = st.button(
        "🚫 Block",
        use_container_width=True
    )


# =========================================================
# CREATE RULE
# =========================================================

if add_rule:

    if not rule_value.strip():

        st.error(
            "Please enter a value for the rule."
        )

    else:

        new_rule = {
            "type": rule_type,
            "value": rule_value.strip()
        }

        try:

            response = requests.post(
                f"{API_URL}/rules",
                json=new_rule,
                timeout=5
            )

            if response.status_code == 200:

                st.success(
                    f"🚫 {rule_type} rule added successfully!"
                )

                st.rerun()

            else:

                st.error(
                    f"Failed to add rule: "
                    f"{response.text}"
                )

        except Exception as e:

            st.error(
                "❌ Cannot connect to FastAPI. "
                "Make sure the backend is running."
            )


# =========================================================
# DISPLAY EXISTING RULES
# =========================================================

st.subheader("📋 Active Security Rules")


if rules:

    for rule in rules:

        rule_id = rule.get("id")
        rule_type = rule.get("type", "UNKNOWN")
        rule_value = rule.get("value", "")
        status = rule.get("status", "Active")

        col1, col2, col3, col4 = st.columns(
            [1.5, 4, 2, 1.5]
        )

        with col1:

            st.write(
                f"**{rule_type}**"
            )

        with col2:

            st.write(
                rule_value
            )

        with col3:

            if status == "Active":

                st.success(
                    "🟢 Active"
                )

            else:

                st.warning(
                    "⚪ Disabled"
                )

        with col4:

            if status == "Active":

                if st.button(
                    "Disable",
                    key=f"disable_{rule_id}"
                ):

                    try:

                        requests.put(
                            f"{API_URL}/rules/"
                            f"{rule_id}/toggle",
                            timeout=5
                        )

                        st.rerun()

                    except Exception:

                        st.error(
                            "Could not update rule."
                        )

            else:

                if st.button(
                    "Enable",
                    key=f"enable_{rule_id}"
                ):

                    try:

                        requests.put(
                            f"{API_URL}/rules/"
                            f"{rule_id}/toggle",
                            timeout=5
                        )

                        st.rerun()

                    except Exception:

                        st.error(
                            "Could not update rule."
                        )


        st.divider()


else:

    st.info(
        "No security rules configured yet."
    )