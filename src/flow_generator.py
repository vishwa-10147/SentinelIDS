import os
import pandas as pd

LIVE_DATA_PATH = "live_data/live_capture.csv"
OUTPUT_FLOW_PATH = "logs/live_flows.csv"

def safe_int(x):
    try:
        if pd.isna(x):
            return 0
        return int(float(x))
    except Exception:
        return 0

def main():
    if not os.path.exists(LIVE_DATA_PATH):
        print(" live_capture.csv not found.")
        return

    df = pd.read_csv(
    LIVE_DATA_PATH,
    engine="python",
    on_bad_lines="skip"
)


    # Keep valid IP packets
    df = df.dropna(subset=["ip.src", "ip.dst"], how="any")

    if df.empty:
        print(" No valid packets found in live_capture.csv.")
        return

    # Clean numeric fields
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce").fillna(0)
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0)
    df["ip.proto"] = pd.to_numeric(df["ip.proto"], errors="coerce").fillna(0)

    for col in ["tcp.dstport", "udp.dstport"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Create one dst_port column (TCP preferred else UDP)
    def get_dst_port(row):
        tcp_d = safe_int(row.get("tcp.dstport", 0))
        udp_d = safe_int(row.get("udp.dstport", 0))
        return tcp_d if tcp_d != 0 else udp_d

    df["dst_port"] = df.apply(get_dst_port, axis=1)

    # Flow ID (basic)
    df["flow_id"] = (
        df["ip.src"].astype(str)
        + " -> "
        + df["ip.dst"].astype(str)
        + " | proto="
        + df["ip.proto"].astype(str)
    )

    flows = df.groupby("flow_id").agg(
        src_ip=("ip.src", "first"),
        dst_ip=("ip.dst", "first"),
        proto=("ip.proto", "first"),
        total_packets=("flow_id", "count"),
        total_bytes=("frame.len", "sum"),
        avg_packet_size=("frame.len", "mean"),
        min_time=("frame.time_epoch", "min"),
        max_time=("frame.time_epoch", "max"),
        unique_dst_ports=("dst_port", lambda x: len(set(x))),
        most_common_dst_port=("dst_port", lambda x: int(x.value_counts().idxmax()) if len(x) > 0 else 0),
    ).reset_index()

    flows["duration_sec"] = (flows["max_time"] - flows["min_time"]).round(4)

    def calc_pps(row):
        if row["duration_sec"] > 0:
            return round(row["total_packets"] / row["duration_sec"], 2)
        return float(row["total_packets"])

    flows["packets_per_sec"] = flows.apply(calc_pps, axis=1)

    os.makedirs("logs", exist_ok=True)
    flows.to_csv(OUTPUT_FLOW_PATH, index=False)

    print(" Flow file generated successfully!")
    print("Saved:", OUTPUT_FLOW_PATH)

    print("\n Top 10 flows by packet count:")
    print(
        flows.sort_values("total_packets", ascending=False).head(10)[
            ["flow_id", "total_packets", "unique_dst_ports", "packets_per_sec", "total_bytes", "duration_sec"]
        ]
    )

if __name__ == "__main__":
    main()
