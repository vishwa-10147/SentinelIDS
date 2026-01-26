import os
import pandas as pd
from datetime import datetime

FLOW_FINAL_PATH = "logs/live_flows_final.csv"
LIVE_CAPTURE_PATH = "live_data/live_capture.csv"
TICKETS_PATH = "logs/soc_tickets.csv"
DEVICE_INVENTORY_PATH = "logs/device_inventory.csv"


def safe_read_csv(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.read_csv(path, engine="python", on_bad_lines="skip")


def get_top_ports_for_attacker(attacker_ip: str, top_n: int = 5):
    pkt_df = safe_read_csv(LIVE_CAPTURE_PATH)
    if pkt_df.empty:
        return []

    if "ip.src" not in pkt_df.columns or "tcp.dstport" not in pkt_df.columns:
        return []

    pkt_df = pkt_df.dropna(subset=["ip.src"])
    pkt_df["tcp.dstport"] = pd.to_numeric(pkt_df["tcp.dstport"], errors="coerce").fillna(0).astype(int)

    attacker_pkts = pkt_df[pkt_df["ip.src"].astype(str) == str(attacker_ip)]
    attacker_pkts = attacker_pkts[attacker_pkts["tcp.dstport"] > 0]

    if attacker_pkts.empty:
        return []

    ports = attacker_pkts["tcp.dstport"].value_counts().head(top_n).index.tolist()
    return ports


def recommend_action(severity: str):
    severity = str(severity).upper()

    if severity == "CRITICAL":
        return "Immediate isolation + block attacker IP + capture PCAP"
    if severity == "HIGH":
        return "Block attacker IP + investigate victim device + review ports"
    if severity == "MEDIUM":
        return "Monitor attacker behavior + watch for escalation"
    return "No action needed"


def build_ticket_key(attacker_ip, victim_ip, category):
    return f"{str(attacker_ip)}|{str(victim_ip)}|{str(category)}"


def load_device_name_map():
    """
    Returns dict: ip -> hostname (clean view)
    If hostname missing, returns "Unknown Device"
    """
    if not os.path.exists(DEVICE_INVENTORY_PATH):
        return {}

    try:
        inv = safe_read_csv(DEVICE_INVENTORY_PATH)
        if inv.empty or "ip" not in inv.columns:
            return {}

        inv.columns = [c.strip().lower() for c in inv.columns]

        if "hostname" not in inv.columns:
            inv["hostname"] = "Unknown"

        inv["ip"] = inv["ip"].astype(str)
        inv["hostname"] = inv["hostname"].astype(str).fillna("Unknown")

        inv = inv.drop_duplicates(subset=["ip"], keep="last")

        inv["hostname_clean"] = inv["hostname"].apply(
            lambda x: x if x not in ["Unknown", "nan", "None", ""] and str(x).strip() != "" else "Unknown Device"
        )

        mapping = dict(zip(inv["ip"], inv["hostname_clean"]))
        return mapping
    except Exception:
        return {}


def get_priority_from_severity(severity: str) -> str:
    """
    Convert severity to priority (P1/P2/P3)
    """
    severity = str(severity).upper()
    if severity == "CRITICAL":
        return "P1"
    elif severity == "HIGH":
        return "P2"
    elif severity == "MEDIUM":
        return "P3"
    else:
        return "P3"


def main():
    df = safe_read_csv(FLOW_FINAL_PATH)

    if df.empty:
        print("[ERROR] live_flows_final.csv is missing or empty. Run flow pipeline first.")
        return

    # Required columns
    for col in [
        "src_ip", "dst_ip", "final_flow_score", "final_severity",
        "advanced_flow_label", "advanced_flow_threat_score"
    ]:
        if col not in df.columns:
            df[col] = "NA"

    # focus only MEDIUM/HIGH/CRITICAL
    focus = df[df["final_severity"].isin(["MEDIUM", "HIGH", "CRITICAL"])].copy()

    if focus.empty:
        print("[OK] No suspicious flows found. No tickets generated.")
        return

    # Load device name mapping
    device_map = load_device_name_map()

    # Load existing tickets (avoid duplicates)
    existing = safe_read_csv(TICKETS_PATH)
    existing_keys = set()

    if not existing.empty and "ticket_key" in existing.columns:
        existing_keys = set(existing["ticket_key"].astype(str).tolist())

    tickets = []
    created_count = 0

    for _, row in focus.iterrows():
        attacker = str(row["src_ip"])
        victim = str(row["dst_ip"])
        severity = str(row["final_severity"])
        score = row.get("final_flow_score", 0)

        category = str(row.get("advanced_flow_label", "NA"))
        adv_score = row.get("advanced_flow_threat_score", 0)

        ticket_key = build_ticket_key(attacker, victim, category)

        # ✅ Skip duplicates (important)
        if ticket_key in existing_keys:
            continue

        ports = get_top_ports_for_attacker(attacker, top_n=5)

        # Get device names
        attacker_device = device_map.get(attacker, "Unknown Device")
        victim_device = device_map.get(victim, "Unknown Device")

        # Get priority from severity
        priority = get_priority_from_severity(severity)

        ticket = {
            "ticket_id": f"TICKET-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{created_count+1:03d}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": severity,
            "priority": priority,
            "attacker_ip": attacker,
            "attacker_device": attacker_device,
            "victim_ip": victim,
            "victim_device": victim_device,
            "attack_category": category,
            "advanced_flow_label": category,
            "advanced_flow_threat_score": adv_score,
            "top_ports": ",".join(map(str, ports)) if ports else "NA",
            "final_flow_score": score,
            "recommendation": recommend_action(severity),

            # ✅ SOC Ticket lifecycle
            "status": "OPEN",
            "notes": "",
            "ticket_key": ticket_key,
        }

        tickets.append(ticket)
        existing_keys.add(ticket_key)
        created_count += 1

    if not tickets:
        print("[OK] No new unique tickets to add.")
        return

    df_new = pd.DataFrame(tickets)

    # Append to existing log
    if not existing.empty:
        df_new = pd.concat([existing, df_new], ignore_index=True)

    os.makedirs("logs", exist_ok=True)
    df_new.to_csv(TICKETS_PATH, index=False)

    print("[OK] SOC Tickets generated!")
    print(f"Saved: {TICKETS_PATH}")
    print(f"New tickets added: {created_count}")
    print(df_new.tail(10))


if __name__ == "__main__":
    main()
