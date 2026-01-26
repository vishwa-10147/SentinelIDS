import os
import glob
import pandas as pd

SAVE_DIR = "datasets/flow_training"
OUTPUT_PATH = "datasets/flow_training/flow_dataset.csv"

def main():
    if not os.path.exists(SAVE_DIR):
        print("❌ datasets/flow_training folder not found.")
        return

    files = glob.glob(os.path.join(SAVE_DIR, "flow_session_*.csv"))

    if len(files) == 0:
        print("❌ No session files found.")
        return

    df_all = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df["session_file"] = os.path.basename(f)
            df_all.append(df)
        except Exception as e:
            print("Skipping file:", f, "Error:", e)

    combined = pd.concat(df_all, ignore_index=True)

    os.makedirs(SAVE_DIR, exist_ok=True)
    combined.to_csv(OUTPUT_PATH, index=False)

    print("✅ Combined dataset created!")
    print("Saved:", OUTPUT_PATH)
    print("Total flows:", len(combined))

    print("\n📌 Class distribution:")
    print(combined["flow_label"].value_counts())

if __name__ == "__main__":
    main()
