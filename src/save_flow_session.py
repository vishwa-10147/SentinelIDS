import os
import pandas as pd
from datetime import datetime

FLOW_LABELED_PATH = "logs/live_flows_labeled.csv"
SAVE_DIR = "datasets/flow_training"

def main():
    if not os.path.exists(FLOW_LABELED_PATH):
        print("❌ live_flows_labeled.csv not found.")
        print("Run first: python src/label_live_flows.py")
        return

    df = pd.read_csv(FLOW_LABELED_PATH)

    if df.empty:
        print("❌ live_flows_labeled.csv is empty.")
        return

    os.makedirs(SAVE_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"flow_session_{timestamp}.csv"
    save_path = os.path.join(SAVE_DIR, filename)

    df.to_csv(save_path, index=False)

    print("✅ Flow session saved successfully!")
    print("Saved:", save_path)
    print("Flows stored:", len(df))

if __name__ == "__main__":
    main()
