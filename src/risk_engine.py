import pandas as pd

DANGEROUS_TCP_PORTS = {21, 22, 23, 25, 135, 139, 445, 3389, 4444, 8080}
NOISY_UDP_PORTS = {1900, 5353}  # SSDP / mDNS

def safe_int(x):
    try:
        if pd.isna(x):
            return 0
        return int(float(x))
    except Exception:
        return 0

def compute_rule_risk(row):
    """
    Returns a rule-based risk score (0-100).
    """
    tcp_dst = safe_int(row.get("tcp.dstport", 0))
    udp_dst = safe_int(row.get("udp.dstport", 0))
    frame_len = safe_int(row.get("frame.len", 0))

    risk = 0
    reasons = []

    # Port risk
    if tcp_dst in DANGEROUS_TCP_PORTS:
        risk += 35
        reasons.append(f"Dangerous TCP destination port: {tcp_dst}")

    if udp_dst in NOISY_UDP_PORTS:
        risk += 20
        reasons.append(f"Noisy UDP discovery port detected: {udp_dst}")

    # Very large frame
    if frame_len > 800:
        risk += 25
        reasons.append(f"Large frame length: {frame_len}")

    # Limit rule risk to 100
    risk = min(risk, 100)

    return risk, reasons

def compute_behavior_risk(df):
    """
    Adds behavior-based risk (packet burst from same src IP).
    """
    df = df.copy()
    df["behavior_risk"] = 0

    # Count packets per source IP
    src_counts = df["ip.src"].value_counts()

    # Behavior rule:
    # if one src IP has too many packets in this capture batch → suspicious
    for ip, count in src_counts.items():
        if count > 200:
            df.loc[df["ip.src"] == ip, "behavior_risk"] = 20
        elif count > 100:
            df.loc[df["ip.src"] == ip, "behavior_risk"] = 10

    return df

def final_threat_score(ml_risk, rule_risk, behavior_risk):
    """
    Final score (0-100):
    - ML risk has 60% weight
    - Rule risk has 30% weight
    - Behavior risk has 10% weight
    """
    try:
        ml_risk = float(ml_risk)
    except:
        ml_risk = 0

    score = (0.60 * ml_risk) + (0.30 * rule_risk) + (0.10 * behavior_risk)
    return round(min(score, 100), 2)
