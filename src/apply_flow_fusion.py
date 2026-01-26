import os
import pandas as pd

FLOW_PRED_PATH = "logs/live_flows_predicted.csv"
FLOW_RULE_PATH = "logs/live_flows_labeled.csv"
FLOW_ADV_PATH  = "logs/live_flows_advanced_labeled.csv"

FLOW_FINAL_PATH = "logs/live_flows_final.csv"


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    elif score >= 65:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def safe_read_csv(path):
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.read_csv(path, engine="python", on_bad_lines="skip")


def main():
    if not os.path.exists(FLOW_PRED_PATH):
        print("[ERROR] live_flows_predicted.csv not found. Run: python src/predict_flow_live.py")
        return

    df_pred = safe_read_csv(FLOW_PRED_PATH)
    if df_pred.empty:
        print("[ERROR] live_flows_predicted.csv is empty.")
        return

    # Base columns we must have from ML prediction output
    for col in [
        "flow_id", "src_ip", "dst_ip",
        "total_packets", "unique_dst_ports",
        "packets_per_sec", "duration_sec",
        "flow_ml_prediction", "flow_ml_confidence_%"
    ]:
        if col not in df_pred.columns:
            df_pred[col] = "NA"

    # Merge Rule Labels (Level 3)
    df_rule = safe_read_csv(FLOW_RULE_PATH)
    if not df_rule.empty and "flow_id" in df_rule.columns:
        if "flow_label" not in df_rule.columns:
            df_rule["flow_label"] = "NORMAL"
        if "flow_threat_score" not in df_rule.columns:
            df_rule["flow_threat_score"] = 0

        df = df_pred.merge(
            df_rule[["flow_id", "flow_label", "flow_threat_score"]],
            on="flow_id",
            how="left"
        )
    else:
        df = df_pred.copy()
        df["flow_label"] = "NORMAL"
        df["flow_threat_score"] = 0

    # Merge Advanced Labels (Level 5)
    df_adv = safe_read_csv(FLOW_ADV_PATH)
    if not df_adv.empty and "flow_id" in df_adv.columns:
        if "advanced_flow_label" not in df_adv.columns:
            df_adv["advanced_flow_label"] = "NORMAL"
        if "advanced_flow_threat_score" not in df_adv.columns:
            df_adv["advanced_flow_threat_score"] = 0

        df = df.merge(
            df_adv[["flow_id", "advanced_flow_label", "advanced_flow_threat_score"]],
            on="flow_id",
            how="left"
        )
    else:
        df["advanced_flow_label"] = "NORMAL"
        df["advanced_flow_threat_score"] = 0

    # Fill missing scores
    df["flow_threat_score"] = pd.to_numeric(df["flow_threat_score"], errors="coerce").fillna(0)
    df["advanced_flow_threat_score"] = pd.to_numeric(df["advanced_flow_threat_score"], errors="coerce").fillna(0)

    # Convert ML confidence to number
    df["flow_ml_confidence_%"] = pd.to_numeric(df["flow_ml_confidence_%"], errors="coerce").fillna(0)

    # Final Fusion Score
    # Weight idea:
    # - ML confidence contributes up to 40 points
    # - Rule engine score contributes up to 30 points
    # - Advanced score contributes up to 40 points
    df["ml_score"] = (df["flow_ml_confidence_%"] / 100) * 40
    df["rule_score"] = (df["flow_threat_score"] / 100) * 30
    df["advanced_score"] = (df["advanced_flow_threat_score"] / 100) * 40

    df["final_flow_score"] = (df["ml_score"] + df["rule_score"] + df["advanced_score"]).round(2)
    df["final_severity"] = df["final_flow_score"].apply(severity_from_score)

    # Output columns
    final_cols = [
        "flow_id",
        "src_ip",
        "dst_ip",
        "total_packets",
        "unique_dst_ports",
        "packets_per_sec",
        "duration_sec",

        "flow_label",
        "flow_threat_score",

        "advanced_flow_label",
        "advanced_flow_threat_score",

        "flow_ml_prediction",
        "flow_ml_confidence_%",

        "final_flow_score",
        "final_severity"
    ]

    for c in final_cols:
        if c not in df.columns:
            df[c] = "NA"

    df_final = df[final_cols].copy()

    os.makedirs("logs", exist_ok=True)
    df_final.to_csv(FLOW_FINAL_PATH, index=False)

    print("\n[OK] Final Flow Fusion Report Saved:", FLOW_FINAL_PATH)

    print("\n[INFO] Top 10 Highest Severity Flows:")
    top = df_final.sort_values("final_flow_score", ascending=False).head(10)
    print(top)


if __name__ == "__main__":
    main()
