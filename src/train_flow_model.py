import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer

from sklearn.ensemble import RandomForestClassifier

DATA_PATH = "datasets/flow_training/flow_dataset.csv"

MODEL_PATH = "models/flow_ids_model.pkl"

def main():
    if not os.path.exists(DATA_PATH):
        print("❌ live_flows_labeled.csv not found.")
        print("Run: python src/label_live_flows.py")
        return

    df = pd.read_csv(DATA_PATH)

    if df.empty:
        print("❌ live_flows_labeled.csv is empty.")
        return

    # Features and target
    target = "flow_label"

    feature_cols = [
        "proto", "total_packets", "total_bytes",
        "avg_packet_size", "duration_sec",
        "packets_per_sec", "unique_dst_ports", "most_common_dst_port"
    ]

    # Ensure all columns exist
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_cols].copy()
    y = df[target].astype(str)

    print("\n✅ Training Flow ML Model")
    print("Total flows:", len(df))
    print("Classes:", sorted(y.unique()))

    # ✅ Stratify only if every class has at least 2 samples
    class_counts = y.value_counts()
    can_stratify = (class_counts.min() >= 2)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.3,
        random_state=42,
        stratify=y if can_stratify else None
    )


    # Preprocessing
    categorical_features = ["proto", "most_common_dst_port"]
    numeric_features = [
        "total_packets", "total_bytes", "avg_packet_size",
        "duration_sec", "packets_per_sec", "unique_dst_ports"
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", "passthrough", numeric_features),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced"
    )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("model", model)
    ])

    # Train
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print("\n🎯 Flow Model Accuracy:", round(acc * 100, 2), "%")

    print("\n📌 Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n📌 Classification Report:")
    print(classification_report(y_test, y_pred))

    # Save
    os.makedirs("models", exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)

    print("\n✅ Flow model saved at:", MODEL_PATH)

if __name__ == "__main__":
    main()
