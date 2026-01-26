import os
import joblib
import pandas as pd

FLOW_INPUT_PATH = "logs/live_flows.csv"
FLOW_MODEL_PATH = "models/flow_ids_model.pkl"
OUTPUT_PATH = "logs/live_flows_predicted.csv"

def main():
    if not os.path.exists(FLOW_INPUT_PATH):
        print(" live_flows.csv not found. Run:")
        print("python src/flow_generator.py")
        return

    if not os.path.exists(FLOW_MODEL_PATH):
        print(" flow_ids_model.pkl not found. Run:")
        print("python src/train_flow_model.py")
        return

    df = pd.read_csv(FLOW_INPUT_PATH)

    if df.empty:
        print(" No flows found in live_flows.csv")
        return

    feature_cols = [
        "proto", "total_packets", "total_bytes",
        "avg_packet_size", "duration_sec",
        "packets_per_sec", "unique_dst_ports", "most_common_dst_port"
    ]

    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_cols].copy()

    model = joblib.load(FLOW_MODEL_PATH)

    df["flow_ml_prediction"] = model.predict(X)

    # Prediction confidence (optional)
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)
            df["flow_ml_confidence_%"] = (proba.max(axis=1) * 100).round(2)
        except:
            df["flow_ml_confidence_%"] = 0.0
    else:
        df["flow_ml_confidence_%"] = 0.0

    df = df.sort_values("total_packets", ascending=False)

    os.makedirs("logs", exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(" Flow ML Predictions saved:", OUTPUT_PATH)
    print("\n Top 10 Predicted Flows:")
    print(df.head(10)[
        ["flow_id", "total_packets", "unique_dst_ports", "packets_per_sec",
         "duration_sec", "flow_ml_prediction", "flow_ml_confidence_%"]
    ])

if __name__ == "__main__":
    main()
