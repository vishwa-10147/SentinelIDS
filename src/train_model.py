import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier

DATA_PATH = "datasets/raw/train_test_network.csv"
MODEL_PATH = "models/ids_random_forest.pkl"

def main():
    print("✅ Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    # Target (Binary)
    target_col = "label"

    # Drop columns we should NOT use directly as features
    drop_cols = ["label", "type"]  # type is attack category; label is target
    X = df.drop(columns=drop_cols)
    y = df[target_col]

    # Separate categorical and numeric columns
    categorical_cols = X.select_dtypes(include=["object"]).columns.tolist()
    numeric_cols = X.select_dtypes(exclude=["object"]).columns.tolist()

    print("\n📌 Total Rows:", df.shape[0])
    print("📌 Total Columns:", df.shape[1])
    print("📌 Categorical Features:", len(categorical_cols))
    print("📌 Numeric Features:", len(numeric_cols))

    # Preprocessing: OneHotEncode categorical data
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
            ("num", "passthrough", numeric_cols)
        ]
    )

    # Model
    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    # Full pipeline (preprocessing + model)
    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model)
        ]
    )

    # Train/test split
    print("\n✅ Splitting dataset (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # Train
    print("\n✅ Training Random Forest model...")
    pipeline.fit(X_train, y_train)

    # Predict
    print("\n✅ Evaluating model...")
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print("\n🎯 Accuracy:", round(acc * 100, 2), "%")

    print("\n📌 Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\n📌 Classification Report:")
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\n✅ Model saved successfully at: {MODEL_PATH}")


if __name__ == "__main__":
    main()
