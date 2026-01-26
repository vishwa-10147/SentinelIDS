def severity_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def fusion_threat_score(flow_label: str, ml_conf: float, rule_score: int) -> int:
    """
    Combine Rule Threat Score + ML behavior prediction confidence
    Output: Final score (0-100)
    """

    flow_label = str(flow_label).upper()

    boost = 0
    if flow_label == "PORTSCAN":
        boost = 20
    elif flow_label == "FLOOD":
        boost = 25
    elif flow_label == "SUSPICIOUS":
        boost = 10
    else:
        boost = 0

    # Confidence bonus
    conf_bonus = 0
    if ml_conf >= 90:
        conf_bonus = 10
    elif ml_conf >= 70:
        conf_bonus = 6
    elif ml_conf >= 50:
        conf_bonus = 3

    final = int(min(rule_score + boost + conf_bonus, 100))
    return final
