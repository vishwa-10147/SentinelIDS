import os
import joblib
import pandas as pd

LIVE_MODEL_PATH = "models/live_ids_model.pkl"
OUTPUT_PATH = "reports/live_feature_importance.csv"

def get_feature_names(preprocessor):
    """
    Extract feature names from ColumnTransformer (OneHotEncoder + numeric passthrough).
    Works for sklearn pipeline.
    """
    feature_names = []

    for name, transformer, cols in preprocessor.transformers_:
        if name == "cat":
            # OneHotEncoder feature names
            ohe = transformer
            try:
                cat_names = ohe.get_feature_names_out(cols)
                feature_names.extend(cat_names)
            except Exception:
                feature_names.extend([f"{c}_encoded" for c in cols])
        elif name == "num":
            # numeric passthrough columns
            feature_names.extend(cols)
        else:
            # dropped or unknown
            pass

    return feature_names

def main():
    if not os.path.exists(LIVE_MODEL_PATH):
        print("❌ Live model not found. Train it first:")
        print("python src/train_live_ids_model.py")
        return

    model = joblib.load(LIVE_MODEL_PATH)

    # pipeline steps
    preprocessor = model.named_steps["preprocessor"]
    clf = model.named_steps["model"]

    # get feature names
    feature_names = get_feature_names(preprocessor)

    # feature importance
    if not hasattr(clf, "feature_importances_"):
        print("❌ This model does not support feature_importances_")
        return

    importances = clf.feature_importances_

    # create df
    df_imp = pd.DataFrame({
        "feature": feature_names,
        "importance": importances
    }).sort_values("importance", ascending=False)

    os.makedirs("reports", exist_ok=True)
    df_imp.to_csv(OUTPUT_PATH, index=False)

    print("✅ Feature Importance Report Generated!")
    print("Saved at:", OUTPUT_PATH)

    print("\nTop 15 Features:")
    print(df_imp.head(15))

if __name__ == "__main__":
    main()
