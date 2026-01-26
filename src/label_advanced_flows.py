import os
import pandas as pd

FLOW_INPUT_PATH = "logs/live_flows.csv"
FLOW_OUTPUT_PATH = "logs/live_flows_advanced_labeled.csv"


def label_advanced_flow(row):
    """
    Advanced Rule Labeling (Level 5)
    Labels:
    - BRUTEFORCE
    - DATA_EXFILTRATION
    - MALWARE_BEACONING
    - DNS_TUNNELING
    - MITM_ARP_SPOOF
    - BOTNET_C2
    - NORMAL
    """

    proto = str(row.get("proto", "")).strip()
    total_packets = float(row.get("total_packets", 0))
    unique_dst_ports = float(row.get("unique_dst_ports", 0))
    packets_per_sec = float(row.get("packets_per_sec", 0))
    total_bytes = float(row.get("total_bytes", 0))
    duration_sec = float(row.get("duration_sec", 0))

    # 1) BRUTEFORCE (TCP only, many packets in short duration, few ports, minimum destination port check)
    # proto=6 means TCP, ignore ICMP (proto=1) and UDP (proto=17) for bruteforce
    # Minimum destination port check: unique_dst_ports >= 1 (at least one port being targeted)
    if (proto == "6" or proto == "6.0") and total_packets > 200 and duration_sec < 30 and unique_dst_ports >= 1 and unique_dst_ports <= 3:
        return "BRUTEFORCE", 85

    # 2) PORTSCAN (too many destination ports)
    if unique_dst_ports >= 200:
        return "PORTSCAN", 100

    # 3) DNS TUNNELING (proto UDP + high packets + long duration)
    # proto=17 means UDP
    if proto == "17.0" and total_packets > 100 and duration_sec > 20:
        return "DNS_TUNNELING", 90

    # 4) DATA EXFILTRATION (huge bytes, continuous, long duration)
    if total_bytes > 2000000 and duration_sec > 10:
        return "DATA_EXFILTRATION", 95

    # 5) MALWARE BEACONING (small repeated packets/sec for long duration)
    if 0.2 <= packets_per_sec <= 5 and duration_sec > 60:
        return "MALWARE_BEACONING", 70

    # 6) BOTNET C2 (low packets/sec but suspicious steady communication)
    if packets_per_sec < 2 and duration_sec > 40 and total_packets > 30:
        return "BOTNET_C2", 75

    # 7) MITM / ARP SPOOF (proto=2 is IGMP? proto=1 ICMP? not exact, so heuristic)
    # Since we don't have ARP packets in flow_generator,
    # we mark ICMP floods + LAN activity as suspicious MITM-like only as demo.
    if proto == "1.0" and total_packets > 200:
        return "MITM_ARP_SPOOF", 80

    return "NORMAL", 0


def main():
    if not os.path.exists(FLOW_INPUT_PATH):
        print(f"[ERROR] Flow input file not found: {FLOW_INPUT_PATH}")
        return

    df = pd.read_csv(FLOW_INPUT_PATH)

    if df.empty:
        print("[WARNING] live_flows.csv is empty. Generate flows again.")
        return

    labels = df.apply(label_advanced_flow, axis=1)

    df["advanced_flow_label"] = labels.apply(lambda x: x[0])
    df["advanced_flow_threat_score"] = labels.apply(lambda x: x[1])

    os.makedirs("logs", exist_ok=True)
    df.to_csv(FLOW_OUTPUT_PATH, index=False)

    print("[OK] Advanced Flow Labeling Completed (Level 5)")
    print(f"Saved: {FLOW_OUTPUT_PATH}")

    print("\n[INFO] Advanced Label Distribution:")
    print(df["advanced_flow_label"].value_counts())

    print("\n[INFO] Top 10 Most Dangerous Advanced Flows:")
    top = df.sort_values("advanced_flow_threat_score", ascending=False).head(10)
    print(top[[
        "flow_id", "src_ip", "dst_ip",
        "total_packets", "unique_dst_ports", "packets_per_sec",
        "duration_sec", "advanced_flow_label", "advanced_flow_threat_score"
    ]])


if __name__ == "__main__":
    main()
