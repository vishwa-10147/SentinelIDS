import os
import time
import joblib
import pandas as pd
from datetime import datetime

DATA_PATH = "datasets/raw/train_test_network.csv"
MODEL_PATH = "models/ids_random_forest.pkl"
LOG_PATH = "logs/detections.csv"

def ensure_logs_folder():
    os.makedirs("logs", exist_ok=True)

def load_model():
    return joblib.load(MODEL_PATH)

def load_data():
    df = pd.read_csv(DATA_PATH)
    # keep label/type only for reference, not for input features
    return df

def predict_once(model, df, sample_size=1):
    sample = df.sample(sample_size, random_state=None).copy()

    # X should NOT include label/type
    X = sample.drop(columns=["label", "type"])

    preds = model.predict(X)

    # Build log rows
    results = []
    for i in range(len(sample)):
        row = sample.iloc[i]
        results.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "proto": row["proto"],
            "service": row["service"],
            "prediction": int(preds[i]),   # 0 normal, 1 attack
            "actual_label": int(row["label"]),
            "attack_type": row["type"]
        })

    return pd.DataFrame(results)

def append_to_log(df_new):
    if os.path.exists(LOG_PATH):
        df_old = pd.read_csv(LOG_PATH)
        df_all = pd.concat([df_old, df_new], ignore_index=True)
    else:
        df_all = df_new

    df_all.to_csv(LOG_PATH, index=False)

def main():
    ensure_logs_folder()

    print("✅ Loading model...")
    model = load_model()

    print("✅ Loading dataset...")
    df = load_data()

    print("✅ Generating predictions and saving logs...")

    # Simulate 50 "live" predictions
    for _ in range(50):
        df_new = predict_once(model, df, sample_size=1)
        append_to_log(df_new)
        print("Logged:", df_new.iloc[0].to_dict())
        time.sleep(0.2)  # adjust speed if needed

    print(f"\n✅ Done! Logs saved to: {LOG_PATH}")

if __name__ == "__main__":
    main()
