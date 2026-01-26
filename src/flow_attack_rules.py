import pandas as pd

def flow_attack_type(row):
    """
    Rule-based flow attack classification
    Output classes:
    - NORMAL
    - PORTSCAN
    - FLOOD
    - SUSPICIOUS
    """

    total_packets = float(row.get("total_packets", 0))
    unique_ports = float(row.get("unique_dst_ports", 0))
    pps = float(row.get("packets_per_sec", 0))
    duration = float(row.get("duration_sec", 0))

    # 1) Portscan: many unique ports, moderate packet rate
    if unique_ports >= 8 and total_packets >= 20:
        return "PORTSCAN"

    # 2) Flood: extremely high packets/sec OR very high packet count in short time
    if pps >= 50 or (total_packets >= 300 and duration <= 5):
        return "FLOOD"

    # 3) Suspicious: moderate anomalies
    if pps >= 20 or total_packets >= 60:
        return "SUSPICIOUS"

    return "NORMAL"


def flow_threat_score(row):
    """
    Flow-level threat score (0-100)
    Based on packet rate + unique ports + packet count
    """

    total_packets = float(row.get("total_packets", 0))
    unique_ports = float(row.get("unique_dst_ports", 0))
    pps = float(row.get("packets_per_sec", 0))

    score = 0

    # packets per second scoring
    if pps >= 200:
        score += 50
    elif pps >= 80:
        score += 30
    elif pps >= 30:
        score += 15

    # unique ports scoring
    if unique_ports >= 15:
        score += 40
    elif unique_ports >= 8:
        score += 25
    elif unique_ports >= 3:
        score += 10

    # total packet scoring
    if total_packets >= 500:
        score += 25
    elif total_packets >= 200:
        score += 15
    elif total_packets >= 50:
        score += 8

    return min(int(score), 100)
