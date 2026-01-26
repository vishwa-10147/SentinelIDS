import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier

DATA_PATH = "datasets/raw/train_test_network.csv"
MODEL_PATH = "models/attack_type_model.pkl"

def main():
    print("✅ Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    # Multi-class target
    target_col = "type"

    # Drop columns we should not use directly as input features
    drop_cols = ["label", "type"]
    X = df.drop(columns=drop_cols)
    y = df[target_col]

    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()
    numeric_cols = X.select_dtypes(exclude=["object"]).columns.tolist()

    print("\n📌 Total Rows:", df.shape[0])
    print("📌 Target Classes:", y.nunique())
    print("📌 Sample Classes:", y.unique()[:10])

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols)
        ]
    )

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model)
        ]
    )

    print("\n✅ Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("\n✅ Training attack-type classifier...")
    pipeline.fit(X_train, y_train)

    print("\n✅ Evaluating attack-type classifier...")
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print("\n🎯 Accuracy:", round(acc * 100, 2), "%")

    print("\n📌 Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n📌 Classification Report:")
    print(classification_report(y_test, y_pred))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"\n✅ Attack-Type model saved at: {MODEL_PATH}")

if __name__ == "__main__":
    main()
