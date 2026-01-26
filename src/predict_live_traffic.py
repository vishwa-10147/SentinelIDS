import os
import time
import joblib
import pandas as pd
from datetime import datetime

LIVE_DATA_PATH = "live_data/live_capture.csv"
LIVE_MODEL_PATH = "models/live_ids_model.pkl"
LIVE_LOG_PATH = "logs/live_detections.csv"

def ensure_logs():
    os.makedirs("logs", exist_ok=True)

def main():
    ensure_logs()

    if not os.path.exists(LIVE_MODEL_PATH):
        print("❌ Live model not found! Train it first:")
        print("python src/train_live_ids_model.py")
        return

    if not os.path.exists(LIVE_DATA_PATH):
        print("❌ live_capture.csv not found! Run Kali capture first.")
        return

    model = joblib.load(LIVE_MODEL_PATH)

    df = pd.read_csv(LIVE_DATA_PATH)

    # Drop rows without IP
    df = df.dropna(subset=["ip.src", "ip.dst"], how="any")

    # Fill missing ports
    for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        df[col] = df[col].fillna(0)

    df["ip.proto"] = df["ip.proto"].fillna(0)
    df["frame.len"] = df["frame.len"].fillna(0)

    # Predict
    y_pred = model.predict(df)

    df_result = df.copy()
    df_result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    df_result["prediction"] = y_pred

    # Save latest results (overwrite for simplicity)
    df_result.to_csv(LIVE_LOG_PATH, index=False)

    print(f"✅ Live predictions saved to: {LIVE_LOG_PATH}")
    print("✅ Total packets predicted:", len(df_result))
    print("⚠ Suspicious packets:", int((df_result['prediction'] == 1).sum()))

if __name__ == "__main__":
    main()
