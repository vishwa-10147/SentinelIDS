import os
import joblib
import pandas as pd
from datetime import datetime

from risk_engine import compute_rule_risk, compute_behavior_risk, final_threat_score

LIVE_MODEL_PATH = "models/live_ids_model.pkl"
LIVE_DATA_PATH = "live_data/live_capture.csv"
OUTPUT_PATH = "logs/live_scored_packets.csv"

def main():
    if not os.path.exists(LIVE_MODEL_PATH):
        print("❌ Live model missing. Train it first.")
        return

    if not os.path.exists(LIVE_DATA_PATH):
        print("❌ live_capture.csv missing.")
        return

    model = joblib.load(LIVE_MODEL_PATH)
    df = pd.read_csv(LIVE_DATA_PATH)

    df = df.dropna(subset=["ip.src", "ip.dst"], how="any")
    if df.empty:
        print("❌ No valid packets found.")
        return

    # Fill missing ports
    for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        if col in df.columns:
            df[col] = df[col].fillna(0)

    df["frame.len"] = df["frame.len"].fillna(0)
    df["ip.proto"] = df["ip.proto"].fillna(0)

    # ML prediction + proba
    df["ml_prediction"] = model.predict(df)

    df["ml_risk_%"] = 0.0
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(df)
            if proba.shape[1] == 2:
                df["ml_risk_%"] = (proba[:, 1] * 100).round(2)
        except:
            pass

    # Rule risk
    rule_risks = []
    rule_reasons = []
    for _, row in df.iterrows():
        rr, reasons = compute_rule_risk(row)
        rule_risks.append(rr)
        rule_reasons.append(" | ".join(reasons) if reasons else "None")

    df["rule_risk"] = rule_risks
    df["rule_reasons"] = rule_reasons

    # Behavior risk
    df = compute_behavior_risk(df)

    # Final score
    df["final_threat_score"] = df.apply(
        lambda r: final_threat_score(r["ml_risk_%"], r["rule_risk"], r["behavior_risk"]),
        axis=1
    )

    df["scored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    os.makedirs("logs", exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print("✅ Threat scoring applied to live packets.")
    print("Saved:", OUTPUT_PATH)
    print("\nTop 10 highest threat packets:")
    print(df.sort_values("final_threat_score", ascending=False)[
        ["ip.src", "ip.dst", "tcp.dstport", "udp.dstport", "frame.len",
         "ml_risk_%", "rule_risk", "behavior_risk", "final_threat_score"]
    ].head(10))

if __name__ == "__main__":
    main()
