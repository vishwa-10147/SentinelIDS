import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier

LIVE_DATA_PATH = "live_data/live_capture.csv"
LIVE_MODEL_PATH = "models/live_ids_model.pkl"

def main():
    if not os.path.exists(LIVE_DATA_PATH):
        print("❌ live_capture.csv not found!")
        print("Run Kali live_capture.sh first.")
        return

    df = pd.read_csv(LIVE_DATA_PATH)

    # Remove completely empty rows (packets without IP)
    df = df.dropna(subset=["ip.src", "ip.dst"], how="any")

    if df.empty or len(df) < 50:
        print("❌ Not enough live packets captured.")
        print("Capture for 30–60 seconds and try again.")
        return

    # Fill missing ports with 0
    for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        df[col] = df[col].fillna(0)

    df["ip.proto"] = df["ip.proto"].fillna(0)
    df["frame.len"] = df["frame.len"].fillna(0)

    # Convert to int safely
    df["ip.proto"] = df["ip.proto"].astype(int, errors="ignore")
    df["frame.len"] = df["frame.len"].astype(int, errors="ignore")

    for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
        df[col] = df[col].astype(int, errors="ignore")

    # ✅ Better rule-based labels (demo realistic)
    # 0 = normal-like, 1 = suspicious/attack-like
    df["label"] = 0

    suspicious_ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 4444, 8080]
    df.loc[df["tcp.dstport"].isin(suspicious_ports), "label"] = 1
    df.loc[df["udp.dstport"].isin([53, 123, 1900, 5353]), "label"] = 1

    # Large frames -> suspicious
    df.loc[df["frame.len"] > 800, "label"] = 1

    # Ensure we have both classes
    counts = df["label"].value_counts()
    print("\n📌 Label Distribution:")
    print(counts)

    if len(counts) < 2:
        print("\n⚠️ Only one class detected in live traffic.")
        print("✅ Solution: Browse websites / run ping / run speedtest and capture again.")
        return

    X = df.drop(columns=["label"])
    y = df["label"]

    categorical_cols = ["ip.src", "ip.dst"]
    numeric_cols = [c for c in X.columns if c not in categorical_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols)
        ]
    )

    model = RandomForestClassifier(
        n_estimators=120,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("model", model)
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("\n✅ LIVE IDS Model Trained")
    print("🎯 Accuracy:", round(accuracy_score(y_test, y_pred) * 100, 2), "%")
    print("\n📌 Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

    print("\n📌 Classification Report:")
    print(classification_report(y_test, y_pred))

    joblib.dump(pipeline, LIVE_MODEL_PATH)
    print(f"\n✅ Saved: {LIVE_MODEL_PATH}")

if __name__ == "__main__":
    main()
