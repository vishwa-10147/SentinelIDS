import os
import pandas as pd
from flow_attack_rules import flow_attack_type, flow_threat_score

FLOW_PATH = "logs/live_flows.csv"
OUTPUT_PATH = "logs/live_flows_labeled.csv"

def main():
    if not os.path.exists(FLOW_PATH):
        print(" live_flows.csv not found. Run this first:")
        print("python src/flow_generator.py")
        return

    df = pd.read_csv(FLOW_PATH)

    if df.empty:
        print(" live_flows.csv is empty.")
        return

    df["flow_label"] = df.apply(flow_attack_type, axis=1)
    df["flow_threat_score"] = df.apply(flow_threat_score, axis=1)

    os.makedirs("logs", exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(" Flow labeling completed.")
    print("Saved:", OUTPUT_PATH)

    print("\n Top 10 Most Dangerous Flows:")
    print(df.sort_values("flow_threat_score", ascending=False).head(10)[
        ["flow_id", "src_ip", "dst_ip", "total_packets", "unique_dst_ports",
         "packets_per_sec", "duration_sec", "flow_label", "flow_threat_score"]
    ])

    print("\n Flow Label Distribution:")
    print(df["flow_label"].value_counts())

if __name__ == "__main__":
    main()
