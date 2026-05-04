import os
import sys
import subprocess

SCRIPTS = [
    "src/apply_risk_engine.py",
    "src/flow_generator.py",
    "src/label_live_flows.py",
    "src/predict_flow_live.py",
    "src/label_advanced_flows.py",   # Level 5
    "src/apply_flow_fusion.py",
    "src/flow_incident_logger.py"
]


def run_script(script_path):
    print("\n" + "=" * 60)
    print(f"[RUN] Running: {script_path}")
    print("=" * 60)

    try:
        subprocess.run([sys.executable, script_path], check=True)
        print(f"\n[OK] Finished: {script_path}")
    except subprocess.CalledProcessError as e:
        print("\n[ERROR] Running Script:")
        print(e)
        sys.exit(1)


def main():
    print("\n[OK] FLOW SOC PIPELINE STARTED")
    print("This will run:")
    for s in SCRIPTS:
        print(f" - {s}")

    for script in SCRIPTS:
        run_script(script)

    print("\n[OK] FLOW SOC PIPELINE COMPLETED SUCCESSFULLY!")
    print("Outputs generated inside logs/:")
    print(" - logs/live_flows.csv")
    print(" - logs/live_flows_labeled.csv")
    print(" - logs/live_flows_predicted.csv")
    print(" - logs/live_flows_advanced_labeled.csv")
    print(" - logs/live_flows_final.csv")
    print(" - logs/flow_incidents.csv")


if __name__ == "__main__":
    main()
