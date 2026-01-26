import os
import pandas as pd
from datetime import datetime

FLOW_FINAL_PATH = "logs/live_flows_final.csv"
FLOW_INCIDENTS_PATH = "logs/flow_incidents.csv"


def load_flow_incidents():
    if os.path.exists(FLOW_INCIDENTS_PATH):
        if os.path.getsize(FLOW_INCIDENTS_PATH) == 0:
            return pd.DataFrame()
        return pd.read_csv(FLOW_INCIDENTS_PATH)
    return pd.DataFrame()


def save_flow_incidents(df):
    os.makedirs("logs", exist_ok=True)
    df.to_csv(FLOW_INCIDENTS_PATH, index=False)


def create_flow_incidents(severity_threshold=("HIGH", "CRITICAL")):
    if not os.path.exists(FLOW_FINAL_PATH):
        print(" live_flows_final.csv not found. Run apply_flow_fusion.py first.")
        return

    df = pd.read_csv(FLOW_FINAL_PATH)

    if df.empty:
        print(" No flows found in live_flows_final.csv")
        return

    # filter only high severity flows
    df_alert = df[df["final_severity"].isin(severity_threshold)].copy()

    if df_alert.empty:
        print(" No HIGH/CRITICAL flows detected. No incident created.")
        return

    incidents = load_flow_incidents()

    new_rows = []
    for _, row in df_alert.iterrows():
        incident_id = f"FLOW-INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        new_rows.append({
            "incident_id": incident_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": row.get("final_severity", "UNKNOWN"),
            "attacker_ip": row.get("src_ip", "NA"),
            "victim_ip": row.get("dst_ip", "NA"),
            "flow_id": row.get("flow_id", "NA"),
            "flow_label": row.get("flow_label", "NA"),
            "final_flow_score": row.get("final_flow_score", 0),
            "rule_threat_score": row.get("rule_threat_score", 0),
            "flow_ml_prediction": row.get("flow_ml_prediction", "NA"),
            "flow_ml_confidence_%": row.get("flow_ml_confidence_%", 0),
        })

    new_df = pd.DataFrame(new_rows)

    # Avoid duplicates: if same attacker/victim/severity already exists recently
    if not incidents.empty:
        combined = pd.concat([incidents, new_df], ignore_index=True)
    else:
        combined = new_df

    save_flow_incidents(combined)

    print(f" Flow incidents updated: {FLOW_INCIDENTS_PATH}")
    print(f"Incidents added: {len(new_df)}")


if __name__ == "__main__":
    create_flow_incidents(severity_threshold=("MEDIUM", "HIGH", "CRITICAL"))

