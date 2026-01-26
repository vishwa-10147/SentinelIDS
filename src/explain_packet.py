import os
import joblib
import pandas as pd

LIVE_MODEL_PATH = "models/live_ids_model.pkl"
LIVE_DATA_PATH = "live_data/live_capture.csv"


def explain_one_packet(sample_row: pd.DataFrame, pipeline):
    """
    Explains a single packet using:
    - model prediction probability
    - rule-based reasons (ports, packet length)
    """
    proba = None
    pred = pipeline.predict(sample_row)[0]

    if hasattr(pipeline, "predict_proba"):
        try:
            proba = pipeline.predict_proba(sample_row)[0][1] * 100
        except Exception:
            proba = None

    row = sample_row.iloc[0]
    reasons = []

    # ✅ Safe int converter (handles NaN)
    def safe_int(x):
        try:
            if pd.isna(x):
                return 0
            return int(float(x))
        except Exception:
            return 0

    tcp_dst = safe_int(row.get("tcp.dstport", 0))
    udp_dst = safe_int(row.get("udp.dstport", 0))
    frame_len = safe_int(row.get("frame.len", 0))

    # Rule-based reasons (interpretable)
    suspicious_ports = [21, 22, 23, 25, 135, 139, 445, 3389, 4444, 8080]

    if tcp_dst in suspicious_ports:
        reasons.append(f"Suspicious TCP destination port: {tcp_dst}")

    if udp_dst in [1900, 5353]:
        reasons.append(f"High-noise UDP discovery port detected: {udp_dst} (SSDP/mDNS traffic)")

    if frame_len > 800:
        reasons.append(f"Large packet size detected: frame.len={frame_len}")

    # If no rules triggered
    if len(reasons) == 0:
        reasons.append("Model detected anomaly pattern based on learned feature combination.")

    return {
        "prediction": int(pred),
        "risk_score_%": round(proba, 2) if proba is not None else "NA",
        "reasons": reasons
    }


def main():
    if not os.path.exists(LIVE_MODEL_PATH):
        print("❌ Live model missing. Train it first.")
        return

    if not os.path.exists(LIVE_DATA_PATH):
        print("❌ live_capture.csv missing. Run Kali capture.")
        return

    df = pd.read_csv(LIVE_DATA_PATH)
    df = df.dropna(subset=["ip.src", "ip.dst"], how="any")

    if df.empty:
        print("❌ No valid rows found in live data.")
        return

    pipeline = joblib.load(LIVE_MODEL_PATH)

    # Take 1 sample randomly
    sample = df.sample(1).copy()

    # Predict + Explain
    result = explain_one_packet(sample, pipeline)

    print("\n✅ Packet Explanation (Local XAI)")
    print("Source IP:", sample.iloc[0].get("ip.src"))
    print("Destination IP:", sample.iloc[0].get("ip.dst"))
    print("TCP dst port:", sample.iloc[0].get("tcp.dstport"))
    print("UDP dst port:", sample.iloc[0].get("udp.dstport"))
    print("Frame length:", sample.iloc[0].get("frame.len"))

    print("\nPrediction:", "SUSPICIOUS" if result["prediction"] == 1 else "NORMAL")
    print("Risk Score (%):", result["risk_score_%"])

    print("\nTop Reasons:")
    for r in result["reasons"]:
        print("-", r)


if __name__ == "__main__":
    main()
