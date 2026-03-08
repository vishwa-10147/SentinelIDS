import os
import sys
import time
import shutil
import subprocess
import joblib
import psutil
import pandas as pd
import streamlit as st
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from streamlit_agraph import agraph, Node, Edge, Config

# ==========================================================
# CONFIG: DEVICE NAMING (Manual Override)
# ==========================================================
DEVICE_NAMES = {
    # Example:
    # "192.168.29.3": "Kali VM",
    # "192.168.29.152": "Victim Laptop",
    # "192.168.29.1": "Router",
}

# ==========================================================
# Paths (Dataset Models)
# ==========================================================
BINARY_MODEL_PATH = "models/ids_random_forest.pkl"
TYPE_MODEL_PATH = "models/attack_type_model.pkl"
DATA_PATH = "datasets/raw/train_test_network.csv"
LOG_PATH = "logs/detections.csv"

# ==========================================================
# Paths (Live Packet IDS Models / Logs)
# ==========================================================
LIVE_DATA_PATH = "live_data/live_capture.csv"
LIVE_MODEL_PATH = "models/live_ids_model.pkl"
LIVE_LOG_PATH = "logs/live_detections.csv"
INCIDENTS_LOG_PATH = "logs/incidents.csv"
LIVE_SCORED_PATH = "logs/live_scored_packets.csv"  # optional

# ==========================================================
# FLOW IDS (Level 4/5)
# ==========================================================
FLOW_FINAL_PATH = "logs/live_flows_final.csv"
FLOW_INCIDENTS_PATH = "logs/flow_incidents.csv"
FLOW_ADVANCED_PATH = "logs/live_flows_advanced_labeled.csv"  # ✅ Level 5 output

# ==========================================================
# Device Inventory
# ==========================================================
DEVICE_INVENTORY_PATH = "logs/device_inventory.csv"
ARP_SHARED_PATH = "live_data/arp_table_kali.csv"
ARP_LOCAL_PATH = "logs/arp_table_kali.csv"

# ==========================================================
# SOC Tickets
# ==========================================================
TICKETS_PATH = "logs/soc_tickets.csv"

# ==========================================================
# Streamlit Setup
# ==========================================================
st.set_page_config(page_title="IoT IDS Dashboard - SOC Premium", layout="wide", initial_sidebar_state="expanded")
st.title("🛡️ IoT Intrusion Detection System (ML-Based)")
st.write("Dataset IDS + Live Packet IDS + Flow IDS Threat Scoring Dashboard (SOC Style)")

# ==========================================================
# Premium SOC Sidebar
# ==========================================================
with st.sidebar:
    st.header("💻 System Health")
    c_cpu, c_mem = st.columns(2)
    cpu_usage = psutil.cpu_percent()
    mem_usage = psutil.virtual_memory().percent
    c_cpu.metric("CPU", f"{cpu_usage}%")
    c_mem.metric("RAM", f"{mem_usage}%")
    
    st.divider()
    st.header("📈 SOC Status")
    st.info("System: ACTIVE")
    st.success("IDS Engine: RUNNING")
    
    st.divider()
    st.header("🛠️ Dashboard Controls")
    if st.button("🚀 Clear All Logs"):
        # Logic to clear all logs
        for log in [LOG_PATH, LIVE_LOG_PATH, INCIDENTS_LOG_PATH, FLOW_FINAL_PATH, FLOW_INCIDENTS_PATH, TICKETS_PATH]:
            if os.path.exists(log):
                os.remove(log)
        st.success("All logs cleared!")
        st.rerun()

    st.divider()
    st.write("v1.1.0-Premium")

# ==========================================================
# Session State
# ==========================================================
if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = set()

# ==========================================================
# Helper functions
# ==========================================================
def threat_level(attack_type: str) -> str:
    attack_type = str(attack_type).lower()
    if attack_type == "normal":
        return "LOW"
    if attack_type in ["scanning", "xss"]:
        return "MEDIUM"
    if attack_type in ["dos", "ddos", "injection"]:
        return "HIGH"
    if attack_type in ["ransomware", "backdoor", "mitm", "password"]:
        return "CRITICAL"
    return "UNKNOWN"


def safe_read_csv(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.read_csv(path, engine="python", on_bad_lines="skip")


def load_device_name_map():
    """
    Returns dict: ip -> hostname (clean view)
    If hostname missing, returns "Unknown Device"
    Manual override DEVICE_NAMES always wins.
    """
    if not os.path.exists(DEVICE_INVENTORY_PATH):
        mapping = {}
        for k, v in DEVICE_NAMES.items():
            mapping[str(k)] = str(v)
        return mapping

    inv = safe_read_csv(DEVICE_INVENTORY_PATH)
    if inv.empty or "ip" not in inv.columns:
        mapping = {}
        for k, v in DEVICE_NAMES.items():
            mapping[str(k)] = str(v)
        return mapping

    inv.columns = [c.strip().lower() for c in inv.columns]

    if "hostname" not in inv.columns:
        inv["hostname"] = "Unknown"

    inv["ip"] = inv["ip"].astype(str)
    inv["hostname"] = inv["hostname"].astype(str).fillna("Unknown")

    inv = inv.drop_duplicates(subset=["ip"], keep="last")

    inv["hostname_clean"] = inv["hostname"].apply(
        lambda x: x if x not in ["Unknown", "nan", "None", ""] and str(x).strip() != "" else "Unknown Device"
    )

    mapping = dict(zip(inv["ip"], inv["hostname_clean"]))

    # ✅ Manual override wins
    for k, v in DEVICE_NAMES.items():
        mapping[str(k)] = str(v)

    return mapping


def run_device_discovery():
    """
    Runs device discovery pipeline:
    - copies arp_table_kali.csv from live_data -> logs/
    - runs python -m src.device_discovery
    """
    try:
        if os.path.exists(ARP_SHARED_PATH):
            os.makedirs("logs", exist_ok=True)
            shutil.copy(ARP_SHARED_PATH, ARP_LOCAL_PATH)
        else:
            st.warning("❌ live_data/arp_table_kali.csv not found. Export ARP scan from Kali first.")
            return False

        # SECURITY FIX: Use subprocess instead of os.system()
        subprocess.run(
            [sys.executable, "-m", "src.device_discovery"],
            capture_output=True,
            text=True,
            timeout=30
        )
        st.success("✅ Device inventory refreshed successfully!")
        return True

    except Exception as e:
        st.error(f"❌ Device inventory refresh failed: {e}")
        return False


def auto_update_device_inventory(interval_seconds: int = 60):
    """
    Auto update device inventory once per interval.
    Prevents too frequent calls using session_state.
    """
    if "last_device_update_time" not in st.session_state:
        st.session_state.last_device_update_time = 0

    now = time.time()
    if now - st.session_state.last_device_update_time < interval_seconds:
        return

    st.session_state.last_device_update_time = now

    try:
        if os.path.exists(ARP_SHARED_PATH):
            os.makedirs("logs", exist_ok=True)
            shutil.copy(ARP_SHARED_PATH, ARP_LOCAL_PATH)

        # SECURITY FIX: Use sys.executable instead of hardcoded "python"
        subprocess.run(
            [sys.executable, "-m", "src.device_discovery"],
            capture_output=True,
            text=True,
            timeout=30
        )
    except Exception:
        pass


def can_run_pipeline(lock_seconds=25):
    """
    Prevent running pipeline too frequently (avoid overload)
    """
    lock_file = "logs/.flow_pipeline_lock.txt"
    os.makedirs("logs", exist_ok=True)

    if os.path.exists(lock_file):
        last_time = os.path.getmtime(lock_file)
        if (datetime.now().timestamp() - last_time) < lock_seconds:
            return False

    with open(lock_file, "w") as f:
        f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return True


def get_top_attack_paths(flow_df: pd.DataFrame, top_n: int = 10):
    """
    Returns top attacker -> victim paths by count (severity focus)
    """
    if flow_df.empty:
        return pd.DataFrame()

    needed = ["src_ip", "dst_ip", "final_severity"]
    for c in needed:
        if c not in flow_df.columns:
            flow_df[c] = "NA"

    focus = flow_df[flow_df["final_severity"].isin(["MEDIUM", "HIGH", "CRITICAL"])].copy()
    if focus.empty:
        return pd.DataFrame()

    paths = (
        focus.groupby(["src_ip", "dst_ip"])
        .size()
        .reset_index(name="flow_count")
        .sort_values("flow_count", ascending=False)
        .head(top_n)
    )
    return paths


def ensure_columns(df: pd.DataFrame, cols: list, default="NA") -> pd.DataFrame:
    for c in cols:
        if c not in df.columns:
            df[c] = default
    return df


def save_tickets_df(df: pd.DataFrame):
    """
    Save tickets DataFrame with proper data cleaning to prevent file corruption.
    Always fills missing values for status and notes before saving.
    """
    if df.empty:
        return

    # Ensure required columns exist
    required_cols = [
        "ticket_id", "timestamp", "severity", "priority",
        "attacker_ip", "attacker_device", "victim_ip", "victim_device",
        "attack_category", "advanced_flow_label", "advanced_flow_threat_score",
        "top_ports", "final_flow_score", "recommendation",
        "status", "notes", "ticket_key"
    ]

    df = ensure_columns(df, required_cols, default="NA")

    # Fill missing status values (default: OPEN)
    df["status"] = df["status"].replace("NA", "OPEN").fillna("OPEN")
    df["status"] = df["status"].astype(str).str.strip()
    # Ensure status is valid
    valid_statuses = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    df["status"] = df["status"].apply(lambda x: x if x in valid_statuses else "OPEN")

    # Fill missing notes values (default: empty string)
    df["notes"] = df["notes"].replace("NA", "").fillna("")
    df["notes"] = df["notes"].astype(str)

    # Fill missing priority if not present
    if "priority" not in df.columns or df["priority"].isna().any():
        df["priority"] = df.get("priority", df.get("severity", "P3").apply(
            lambda s: "P1" if str(s).upper() == "CRITICAL" else ("P2" if str(s).upper() == "HIGH" else "P3")
        ))

    # Ensure all string columns are properly formatted
    for col in df.columns:
        if df[col].dtype == "object":
            df[col] = df[col].astype(str).replace("nan", "").replace("None", "")

    os.makedirs("logs", exist_ok=True)
    df.to_csv(TICKETS_PATH, index=False)


# ==========================================================
# Model Loaders
# ==========================================================
@st.cache_resource
def load_binary_model():
    return joblib.load(BINARY_MODEL_PATH)


@st.cache_resource
def load_type_model():
    return joblib.load(TYPE_MODEL_PATH)


@st.cache_data
def load_dataset():
    return pd.read_csv(DATA_PATH)


@st.cache_resource
def load_live_model():
    return joblib.load(LIVE_MODEL_PATH)


# ==========================================================
# Dataset log helpers
# ==========================================================
def load_logs():
    required_cols = [
        "timestamp", "src_ip", "dst_ip", "proto", "service",
        "binary_prediction", "attack_type_prediction", "threat_level",
        "actual_label", "actual_type"
    ]

    if os.path.exists(LOG_PATH):
        df_logs = safe_read_csv(LOG_PATH)

        if "prediction" in df_logs.columns and "binary_prediction" not in df_logs.columns:
            df_logs["binary_prediction"] = df_logs["prediction"]

        if "attack_type" in df_logs.columns and "actual_type" not in df_logs.columns:
            df_logs["actual_type"] = df_logs["attack_type"]

        if "attack_type_prediction" not in df_logs.columns:
            df_logs["attack_type_prediction"] = "NA"

        if "threat_level" not in df_logs.columns:
            df_logs["threat_level"] = "NA"

        for col in required_cols:
            if col not in df_logs.columns:
                df_logs[col] = "NA"

        return df_logs[required_cols]

    return pd.DataFrame(columns=required_cols)


def save_logs(df_logs):
    os.makedirs("logs", exist_ok=True)
    df_logs.to_csv(LOG_PATH, index=False)


def clear_logs():
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)


def save_live_logs(df_live):
    os.makedirs("logs", exist_ok=True)
    df_live.to_csv(LIVE_LOG_PATH, index=False)


# ==========================================================
# Incident log helpers
# ==========================================================
def load_incidents():
    cols = [
        "incident_id", "timestamp", "severity",
        "suspicious_packets", "high_risk_packets",
        "top_suspicious_src_ip"
    ]

    if os.path.exists(INCIDENTS_LOG_PATH):
        if os.path.getsize(INCIDENTS_LOG_PATH) == 0:
            return pd.DataFrame(columns=cols)

        df = safe_read_csv(INCIDENTS_LOG_PATH)
        df = ensure_columns(df, cols, default="NA")
        return df[cols]

    return pd.DataFrame(columns=cols)


# ==========================================================
# Tabs
# ==========================================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📘 Dataset IDS (TON_IoT)",
    "📡 Live Packet IDS (Real-Time)",
    "📊 Flow IDS Monitoring",
    "🌐 Global SOC Visuals"
])

# ==========================================================
# TAB 1: Dataset IDS
# ==========================================================
with tab1:
    st.subheader("Dataset IDS - Two Level Detection (Research Dataset Mode)")

    binary_model = load_binary_model()
    type_model = load_type_model()
    df = load_dataset()
    logs = load_logs()

    if st.button("🗑️ Clear Dataset Logs"):
        clear_logs()
        st.success("Dataset logs cleared.")
        st.rerun()

    total_logs = len(logs)
    total_attacks = (logs["binary_prediction"] == 1).sum() if total_logs else 0
    total_normal = (logs["binary_prediction"] == 0).sum() if total_logs else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Logs", total_logs)
    c2.metric("Predicted Attacks", total_attacks)
    c3.metric("Predicted Normal", total_normal)
    c4.metric("Dataset Rows", df.shape[0])

    st.divider()
    st.subheader("Run Quick Detection (1 Dataset Record)")

    if st.button("Run Dataset Detection"):
        sample = df.sample(1).copy()
        X = sample.drop(columns=["label", "type"])

        binary_pred = int(binary_model.predict(X)[0])
        attack_type_pred = str(type_model.predict(X)[0])
        level = threat_level(attack_type_pred)

        st.success(f"Binary Prediction: {'ATTACK' if binary_pred == 1 else 'NORMAL'}")
        st.info(f"Attack Type Prediction: {attack_type_pred.upper()}")
        st.warning(f"Threat Level: {level}")

        new_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": sample.iloc[0]["src_ip"],
            "dst_ip": sample.iloc[0]["dst_ip"],
            "proto": sample.iloc[0]["proto"],
            "service": sample.iloc[0]["service"],
            "binary_prediction": binary_pred,
            "attack_type_prediction": attack_type_pred,
            "threat_level": level,
            "actual_label": int(sample.iloc[0]["label"]),
            "actual_type": sample.iloc[0]["type"],
        }

        logs = pd.concat([logs, pd.DataFrame([new_log])], ignore_index=True)
        save_logs(logs)

        st.write("Sample Record Details:")
        st.dataframe(sample, use_container_width=True)

    st.divider()
    st.subheader("Dataset Detection Logs")
    st.dataframe(logs.tail(50), use_container_width=True)

    st.divider()
    st.subheader("Dataset Analytics")

    if len(logs) > 0:
        col1, col2 = st.columns(2)
        with col1:
            st.write("Attack vs Normal")
            st.bar_chart(logs["binary_prediction"].value_counts().rename(index={0: "Normal", 1: "Attack"}))
        with col2:
            st.write("Threat Level Distribution")
            st.bar_chart(logs["threat_level"].value_counts())

        st.write("Attack Type Distribution")
        st.bar_chart(logs["attack_type_prediction"].value_counts())
    else:
        st.info("No dataset logs yet. Run Dataset Detection.")


# ==========================================================
# TAB 2: Live Packet IDS
# ==========================================================
with tab2:
    st.subheader("Live Packet IDS (Real-Time SOC Monitoring)")
    st.write("Kali captures traffic → CSV shared to Windows → ML detects suspicious packets.")

    auto_update_device_inventory(interval_seconds=60)

    st.subheader("🖥️ Device Identification")
    if st.button("🔄 Refresh Device Inventory Now", key="refresh_inv_tab2"):
        run_device_discovery()
        st.rerun()

    st.divider()

    auto_refresh_on = st.checkbox("✅ Auto Refresh Packet View (5 sec)", value=True)
    if auto_refresh_on:
        st_autorefresh(interval=5000, key="live_refresh_key_packets")

    alert_threshold = st.slider("🚨 Alert if Suspicious Packets >", 10, 5000, 100)
    high_risk_threshold = st.slider("🔥 High-Risk Probability Alert (%)", 50, 100, 80)
    show_rows = st.slider("Show last N packets", 20, 2000, 200)

    if not os.path.exists(LIVE_DATA_PATH):
        st.error("❌ live_capture.csv not found in live_data/. Start Kali capture first.")
        st.stop()

    if not os.path.exists(LIVE_MODEL_PATH):
        st.error("❌ live_ids_model.pkl not found. Train live model first.")
        st.stop()

    live_df = safe_read_csv(LIVE_DATA_PATH)
    live_df = live_df.dropna(subset=["ip.src", "ip.dst"], how="any")

    if live_df.empty:
        st.warning("⚠️ No valid IP packets yet. Capture again for 30–60 seconds.")
        st.stop()

    for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        if col in live_df.columns:
            live_df[col] = live_df[col].fillna(0)

    if "ip.proto" in live_df.columns:
        live_df["ip.proto"] = live_df["ip.proto"].fillna(0)

    if "frame.len" in live_df.columns:
        live_df["frame.len"] = live_df["frame.len"].fillna(0)

    live_model = load_live_model()

    preds = live_model.predict(live_df)
    live_df["prediction"] = preds
    live_df["prediction_label"] = live_df["prediction"].apply(lambda x: "SUSPICIOUS" if x == 1 else "NORMAL")

    live_df["risk_score_%"] = 0.0
    if hasattr(live_model, "predict_proba"):
        try:
            proba = live_model.predict_proba(live_df)
            if proba.shape[1] == 2:
                live_df["risk_score_%"] = (proba[:, 1] * 100).round(2)
        except Exception:
            pass

    device_map = load_device_name_map()
    live_df["src_device"] = live_df["ip.src"].astype(str).apply(lambda ip: device_map.get(ip, "Unknown Device"))
    live_df["dst_device"] = live_df["ip.dst"].astype(str).apply(lambda ip: device_map.get(ip, "Unknown Device"))

    live_df["is_blocked_src_ip"] = live_df["ip.src"].astype(str).apply(
        lambda x: "YES" if x in st.session_state.blocked_ips else "NO"
    )

    total_packets = len(live_df)
    suspicious_packets = int((live_df["prediction"] == 1).sum())
    normal_packets = int((live_df["prediction"] == 0).sum())
    high_risk_count = int((live_df["risk_score_%"] >= high_risk_threshold).sum())

    save_live_logs(live_df)

    st.info(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if suspicious_packets > alert_threshold:
        st.error(f"🚨 LIVE ALERT: High suspicious traffic detected! ({suspicious_packets} suspicious packets)")
    else:
        st.success(f"✅ Traffic Status: Stable ({suspicious_packets} suspicious packets)")

    if high_risk_count > 0:
        st.warning(f"🔥 High Risk Packets: {high_risk_count} packets >= {high_risk_threshold}% risk score")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Packets", total_packets)
    m2.metric("Suspicious", suspicious_packets)
    m3.metric("Normal", normal_packets)
    m4.metric("High-Risk", high_risk_count)

    st.divider()
    st.subheader("🔥 Top 5 High-Risk Packets (SOC Priority View)")
    top_risk = live_df.sort_values("risk_score_%", ascending=False).head(5)

    show_cols = [
        "src_device", "ip.src", "dst_device", "ip.dst", "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport",
        "frame.len", "prediction_label", "risk_score_%", "is_blocked_src_ip"
    ]
    show_cols = [c for c in show_cols if c in live_df.columns]

    st.dataframe(top_risk[show_cols], use_container_width=True)

    st.divider()
    st.subheader("Live Predictions Table")

    show_cols2 = [
        "frame.time_epoch", "src_device", "ip.src",
        "dst_device", "ip.dst",
        "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport",
        "frame.len", "prediction_label", "risk_score_%", "is_blocked_src_ip"
    ]
    show_cols2 = [c for c in show_cols2 if c in live_df.columns]

    st.dataframe(live_df[show_cols2].tail(show_rows), use_container_width=True)

    st.divider()
    st.subheader("Download Live Detection Report")

    st.download_button(
        label="Download live_detections.csv",
        data=live_df.to_csv(index=False),
        file_name="live_detections.csv",
        mime="text/csv"
    )


# ==========================================================
# TAB 3: FLOW IDS Monitoring (Level 4/5)
# ==========================================================
with tab3:
    st.subheader(" Flow IDS Monitoring (SOC View)")
    st.write("Flow behavior analysis + Flow ML prediction + Fusion scoring + Level 5 Advanced rules.")

    auto_update_device_inventory(interval_seconds=60)

    st.subheader("🖥️ Device Identification")
    if st.button("🔄 Refresh Device Inventory (Flow View)", key="refresh_inv_tab3"):
        run_device_discovery()
        st.rerun()

    st.divider()
    st.subheader("⚙️ Flow SOC Automation")

    col_auto1, col_auto2 = st.columns(2)
    with col_auto1:
        auto_run_pipeline = st.checkbox("✅ Auto Run Flow SOC Pipeline (every 30 sec)", value=False)
    with col_auto2:
        auto_refresh_flow = st.checkbox("✅ Auto Refresh Flow View (5 sec)", value=True)

    if auto_run_pipeline:
        st_autorefresh(interval=30000, key="auto_flow_soc_pipeline_refresh")
        if can_run_pipeline(lock_seconds=25):
            with st.spinner("Running Flow SOC Pipeline..."):
                # SECURITY FIX: Use subprocess instead of os.system()
                subprocess.run(
                    [sys.executable, "src/run_flow_soc_pipeline.py"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

    if auto_refresh_flow:
        st_autorefresh(interval=5000, key="flow_refresh_key")

    st.divider()

    colR1, colR2 = st.columns([1, 2])
    with colR1:
        if st.button("🚀 Run Flow SOC Pipeline Now"):
            st.info("Running Flow SOC pipeline...")
            # SECURITY FIX: Use subprocess instead of os.system()
            result = subprocess.run(
                [sys.executable, "src/run_flow_soc_pipeline.py"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                st.success("✅ Flow SOC Pipeline completed. Dashboard updated.")
            else:
                st.error(f"❌ Pipeline failed: {result.stderr[:200]}")
            st.rerun()

    with colR2:
        st.write("Pipeline generates:")
        st.code(
            "logs/live_flows.csv\n"
            "logs/live_flows_labeled.csv\n"
            "logs/live_flows_predicted.csv\n"
            "logs/live_flows_advanced_labeled.csv\n"
            "logs/live_flows_final.csv\n"
            "logs/flow_incidents.csv"
        )

    if not os.path.exists(FLOW_FINAL_PATH):
        st.error("❌ logs/live_flows_final.csv not found. Run pipeline first.")
        st.stop()

    flow_final_df = safe_read_csv(FLOW_FINAL_PATH)
    if flow_final_df.empty:
        st.warning("⚠️ live_flows_final.csv is empty.")
        st.stop()

    # ✅ Merge Level 5 Advanced Labels into final flows
    if os.path.exists(FLOW_ADVANCED_PATH):
        adv_df = safe_read_csv(FLOW_ADVANCED_PATH)
        if not adv_df.empty and "flow_id" in adv_df.columns:
            adv_keep_cols = ["flow_id", "advanced_flow_label", "advanced_flow_threat_score"]
            adv_df = ensure_columns(adv_df, adv_keep_cols, default="NA")
            adv_df = adv_df[adv_keep_cols].drop_duplicates(subset=["flow_id"], keep="last")

            flow_final_df = flow_final_df.merge(adv_df, on="flow_id", how="left")

    if "advanced_flow_label" not in flow_final_df.columns:
        flow_final_df["advanced_flow_label"] = "NORMAL"
    if "advanced_flow_threat_score" not in flow_final_df.columns:
        flow_final_df["advanced_flow_threat_score"] = 0

    needed_cols = [
        "flow_id", "src_ip", "dst_ip",
        "final_flow_score", "rule_threat_score",
        "flow_ml_prediction", "flow_ml_confidence_%", "final_severity"
    ]
    flow_final_df = ensure_columns(flow_final_df, needed_cols, default="NA")

    device_map = load_device_name_map()
    flow_final_df["attacker_device"] = flow_final_df["src_ip"].astype(str).apply(lambda ip: device_map.get(ip, "Unknown Device"))
    flow_final_df["victim_device"] = flow_final_df["dst_ip"].astype(str).apply(lambda ip: device_map.get(ip, "Unknown Device"))

    st.info(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Metrics
    sev_counts = flow_final_df["final_severity"].value_counts()
    low_count = int(sev_counts.get("LOW", 0))
    med_count = int(sev_counts.get("MEDIUM", 0))
    high_count = int(sev_counts.get("HIGH", 0))
    crit_count = int(sev_counts.get("CRITICAL", 0))

    a1, a2, a3, a4, a5 = st.columns(5)
    a1.metric("Total Flows", len(flow_final_df))
    a2.metric("LOW", low_count)
    a3.metric("MEDIUM", med_count)
    a4.metric("HIGH", high_count)
    a5.metric("CRITICAL", crit_count)

    if crit_count > 0:
        st.error(f"🚨 CRITICAL FLOWS DETECTED: {crit_count}")
    elif high_count > 0:
        st.warning(f"⚠️ HIGH severity flows detected: {high_count}")
    elif med_count > 0:
        st.info(f"ℹ️ MEDIUM suspicious flows detected: {med_count}")
    else:
        st.success("✅ Flow status: LOW risk network behavior")

    st.divider()

    # ✅ SOC Focus DF
    soc_focus_df = flow_final_df[
        (flow_final_df["flow_ml_prediction"].astype(str) != "NORMAL") |
        (flow_final_df["final_severity"].isin(["MEDIUM", "HIGH", "CRITICAL"]))
    ].copy()

    st.subheader("🎯 TAB 3: SOC Intelligence (Top Attacker / Victim / Scanning Ports)")
    colA, colB, colC = st.columns(3)

    with colA:
        st.write("Top Attacker IPs (Source)")
        if soc_focus_df.empty:
            st.info("No suspicious/high flows yet.")
        else:
            top_attackers = soc_focus_df["src_ip"].value_counts().head(10).reset_index()
            top_attackers.columns = ["attacker_ip", "count"]
            st.dataframe(top_attackers, use_container_width=True)

    with colB:
        st.write("Top Victim IPs (Destination)")
        if soc_focus_df.empty:
            st.info("No suspicious/high flows yet.")
        else:
            top_victims = soc_focus_df["dst_ip"].value_counts().head(10).reset_index()
            top_victims.columns = ["victim_ip", "count"]
            st.dataframe(top_victims, use_container_width=True)

    with colC:
        st.write("Top Scanning Ports (REAL from live_capture.csv)")
        pkt_df = safe_read_csv(LIVE_DATA_PATH)
        if pkt_df.empty or "ip.src" not in pkt_df.columns or "tcp.dstport" not in pkt_df.columns:
            st.info("TCP destination ports not available in packet capture yet.")
        else:
            pkt_df["tcp.dstport"] = pd.to_numeric(pkt_df["tcp.dstport"], errors="coerce").fillna(0).astype(int)
            pkt_df = pkt_df[pkt_df["tcp.dstport"] > 0]
            if pkt_df.empty:
                st.info("No TCP ports detected yet.")
            else:
                top_ports = pkt_df["tcp.dstport"].value_counts().head(10).reset_index()
                top_ports.columns = ["tcp_dst_port", "count"]
                st.dataframe(top_ports, use_container_width=True)

    st.divider()
    st.subheader("🔥 Top High Severity Flows (Final Fusion Output)")

    view_cols = [
        "flow_id",
        "attacker_device", "src_ip",
        "victim_device", "dst_ip",
        "total_packets",
        "unique_dst_ports",
        "packets_per_sec",
        "duration_sec",
        "advanced_flow_label",
        "advanced_flow_threat_score",
        "flow_ml_prediction",
        "flow_ml_confidence_%",
        "rule_threat_score",
        "final_flow_score",
        "final_severity"
    ]
    flow_final_df = ensure_columns(flow_final_df, view_cols, default="NA")

    try:
        flow_final_df["final_flow_score"] = pd.to_numeric(flow_final_df["final_flow_score"], errors="coerce").fillna(0)
    except Exception:
        flow_final_df["final_flow_score"] = 0

    flow_final_df = flow_final_df.sort_values("final_flow_score", ascending=False)

    st.dataframe(flow_final_df[view_cols].head(25), use_container_width=True)

    st.divider()
    st.subheader("📊 Flow Severity Distribution")
    st.bar_chart(flow_final_df["final_severity"].value_counts())

    st.divider()
    st.subheader("🎯 Level 5: Advanced Attack Categories")

    adv_counts = flow_final_df["advanced_flow_label"].value_counts()
    col_adv1, col_adv2 = st.columns(2)

    with col_adv1:
        st.write("Attack Category Distribution")
        st.bar_chart(adv_counts)

    with col_adv2:
        st.write("Category Counts")
        adv_table = adv_counts.reset_index()
        adv_table.columns = ["Attack Category", "Count"]
        st.dataframe(adv_table, use_container_width=True)

    adv_attacks = flow_final_df[flow_final_df["advanced_flow_label"] != "NORMAL"]
    if not adv_attacks.empty:
        st.write("🔥 Detected Advanced Threats")
        adv_cols = [
            "flow_id", "src_ip", "dst_ip",
            "advanced_flow_label", "advanced_flow_threat_score",
            "final_severity"
        ]
        adv_attacks = ensure_columns(adv_attacks, adv_cols, default="NA")
        st.dataframe(adv_attacks[adv_cols].head(30), use_container_width=True)
    else:
        st.success("✅ No advanced threats detected in current flows")

    st.divider()
    st.subheader("⬇️ Download Flow SOC Report")

    st.download_button(
        label="Download live_flows_final.csv",
        data=flow_final_df.to_csv(index=False),
        file_name="live_flows_final.csv",
        mime="text/csv"
    )

    st.divider()
    st.subheader("📌 Flow Incident Timeline")

    if os.path.exists(FLOW_INCIDENTS_PATH):
        flow_incidents = safe_read_csv(FLOW_INCIDENTS_PATH)
        if flow_incidents.empty:
            st.info("No flow incidents logged yet.")
        else:
            st.metric("Total Flow Incidents", len(flow_incidents))
            st.dataframe(flow_incidents.tail(25), use_container_width=True)
    else:
        st.info("No flow_incidents.csv found yet. Run: python src/flow_incident_logger.py")

    st.divider()
    st.subheader("🎫 SOC Tickets (Auto Generated)")

    colT1, colT2, colT3 = st.columns(3)

    with colT1:
        if st.button("📝 Generate SOC Tickets Now"):
            # SECURITY FIX: Use subprocess instead of os.system()
            result = subprocess.run(
                [sys.executable, "src/soc_ticket_generator.py"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                st.success("✅ SOC tickets generated!")
            else:
                st.error(f"❌ Ticket generation failed: {result.stderr[:200]}")
            st.rerun()

    with colT2:
        if st.button("🔄 Refresh Tickets View"):
            st.rerun()

    with colT3:
        if st.button("🧹 Clear SOC Tickets"):
            if os.path.exists(TICKETS_PATH):
                os.remove(TICKETS_PATH)
            st.success("✅ Tickets cleared!")
            st.rerun()

    tickets_df = safe_read_csv(TICKETS_PATH)

    if tickets_df.empty:
        st.info("No SOC tickets yet. Click 'Generate SOC Tickets Now'")
    else:
        needed_ticket_cols = [
            "ticket_id", "timestamp", "severity", "priority",
            "attacker_ip", "attacker_device", "victim_ip", "victim_device",
            "top_ports", "final_flow_score",
            "recommendation",
            "advanced_flow_label", "advanced_flow_threat_score",
            "status", "notes", "ticket_key"
        ]
        tickets_df = ensure_columns(tickets_df, needed_ticket_cols, default="NA")
        # Use save function to ensure proper formatting (but don't save yet, just clean)
        tickets_df["status"] = tickets_df["status"].replace("NA", "OPEN").fillna("OPEN")
        tickets_df["notes"] = tickets_df["notes"].replace("NA", "").fillna("")

        st.metric("Total SOC Tickets", len(tickets_df))
        st.dataframe(tickets_df.tail(40), use_container_width=True)

        st.download_button(
            label="Download soc_tickets.csv",
            data=tickets_df.to_csv(index=False),
            file_name="soc_tickets.csv",
            mime="text/csv"
        )

        st.divider()
        st.subheader("🛠️ Ticket Update Panel (Status + Notes)")

        ticket_ids = tickets_df["ticket_id"].dropna().astype(str).tolist()

        if ticket_ids:
            selected_ticket = st.selectbox("Select Ticket ID", ticket_ids)

            row_match = tickets_df[tickets_df["ticket_id"].astype(str) == str(selected_ticket)]
            if not row_match.empty:
                current_row = row_match.iloc[0]
            else:
                current_row = {}

            colU1, colU2 = st.columns(2)

            with colU1:
                new_status = st.selectbox(
                    "Update Status",
                    options=["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"],
                    index=0
                )

            with colU2:
                new_notes = st.text_area(
                    "Update Notes",
                    value=str(current_row.get("notes", "")),
                    height=120
                )

            if st.button("✅ Save Ticket Update"):
                # Update the ticket
                mask = tickets_df["ticket_id"].astype(str) == str(selected_ticket)
                tickets_df.loc[mask, "status"] = new_status
                tickets_df.loc[mask, "notes"] = new_notes

                # Save using proper function
                save_tickets_df(tickets_df)

                st.success(f"✅ Updated Ticket: {selected_ticket}")
                st.rerun()

# ==========================================================
# TAB 4: Global SOC Visuals & Graph
# ==========================================================
with tab4:
    st.subheader("🌐 Global SOC Visual Analytics")
    
    col_v1, col_v2 = st.columns([2, 1])
    
    with col_v1:
        st.write("### 🕸️ Interactive Network Traffic Graph")
        st.write("Visualizing real-time connections between devices (Top flows)")
        
        # Load flow data for graph
        if os.path.exists(FLOW_FINAL_PATH):
            flow_data = safe_read_csv(FLOW_FINAL_PATH)
            if not flow_data.empty:
                # Get top flows to avoid graph clutter
                top_flows = flow_data.sort_values("final_flow_score", ascending=False).head(20)
                
                nodes = []
                edges = []
                node_set = set()
                
                device_map = load_device_name_map()
                
                for _, row in top_flows.iterrows():
                    src = str(row["src_ip"])
                    dst = str(row["dst_ip"])
                    sev = str(row["final_severity"])
                    
                    if src not in node_set:
                        nodes.append(Node(id=src, label=device_map.get(src, src), size=25, color="#00ff00"))
                        node_set.add(src)
                    
                    if dst not in node_set:
                        nodes.append(Node(id=dst, label=device_map.get(dst, dst), size=25, color="#0000ff"))
                        node_set.add(dst)
                    
                    edge_color = "#666666"
                    if sev == "CRITICAL": edge_color = "#ff0000"
                    elif sev == "HIGH": edge_color = "#ffa500"
                    
                    edges.append(Edge(source=src, target=dst, label=sev, color=edge_color))
                
                config = Config(width=800, height=600, directed=True, nodeHighlightBehavior=True, highlightColor="#F7A7A6", staticGraphWithDragAndDrop=True)
                
                agraph(nodes=nodes, edges=edges, config=config)
            else:
                st.info("No flow data available for graph.")
        else:
            st.info("Run Flow SOC Pipeline to generate graph data.")

    with col_v2:
        st.write("### 📄 SOC Reporting")
        st.write("Generate a professional PDF summary of recent incidents and SOC status.")
        
        if st.button("📊 Generate PDF SOC Report", use_container_width=True):
            with st.spinner("Generating PDF Report..."):
                try:
                    # Check if script exists
                    report_script = "src/generate_pdf_report.py"
                    if os.path.exists(report_script):
                        result = subprocess.run(
                            [sys.executable, report_script],
                            capture_output=True,
                            text=True,
                            timeout=60
                        )
                        if result.returncode == 0:
                            st.success("✅ PDF Report Generated: reports/SOC_Summary_Report.pdf")
                            
                            # Provide download button
                            report_path = "reports/SOC_Summary_Report.pdf"
                            if os.path.exists(report_path):
                                with open(report_path, "rb") as f:
                                    st.download_button(
                                        label="⬇️ Download PDF Report",
                                        data=f,
                                        file_name="SOC_Summary_Report.pdf",
                                        mime="application/pdf"
                                    )
                        else:
                            st.error(f"❌ Report generation failed: {result.stderr[:200]}")
                    else:
                        st.error("❌ src/generate_pdf_report.py not found.")
                except Exception as e:
                    st.error(f"❌ Error: {e}")

        st.divider()
        st.write("### 🛡️ SOC Recommendations")
        st.success("1. Monitor CRITICAL flows immediately.")
        st.info("2. Update device inventory weekly.")
        st.warning("3. Ensure firewall rules are synchronized.")
