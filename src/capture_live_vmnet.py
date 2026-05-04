import argparse
import csv
import os
import time
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, get_if_list, sniff
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:  # pragma: no cover
        get_windows_if_list = None
except ImportError:  # pragma: no cover
    get_if_list = None
    sniff = None
    IP = TCP = UDP = None
    get_windows_if_list = None


LIVE_CAPTURE_PATH = "live_data/live_capture.csv"
LIVE_PREDICTIONS_PATH = "logs/live_detections.csv"
DEFAULT_INTERFACE_HINT = "VMware Network Adapter VMnet1"

CSV_HEADERS = [
    "frame.time_epoch",
    "packet.registered_at",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
]


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def list_interfaces():
    if get_if_list is None:
        return []
    try:
        return get_if_list()
    except Exception:
        return []


def resolve_interface(interface_name=None, interface_hint=DEFAULT_INTERFACE_HINT):
    interfaces = list_interfaces()
    if not interfaces:
        return None, []

    # Windows: use richer metadata to map VMware adapter descriptions to NPF names
    if get_windows_if_list is not None:
        try:
            win_ifaces = get_windows_if_list()
            metadata = []
            for item in win_ifaces:
                npf_name = item.get("name") or ""
                desc = item.get("description") or ""
                metadata.append((npf_name, desc))

            if interface_name:
                for npf_name, desc in metadata:
                    if interface_name.lower() in npf_name.lower() or interface_name.lower() in desc.lower():
                        return npf_name, interfaces

            if interface_hint:
                for npf_name, desc in metadata:
                    if interface_hint.lower() in npf_name.lower() or interface_hint.lower() in desc.lower():
                        return npf_name, interfaces

            for npf_name, desc in metadata:
                if "vmware" in desc.lower() or "vmnet" in desc.lower():
                    return npf_name, interfaces
        except Exception:
            pass

    if interface_name and interface_name in interfaces:
        return interface_name, interfaces

    if interface_name:
        for iface in interfaces:
            if interface_name.lower() in iface.lower():
                return iface, interfaces

    for iface in interfaces:
        if interface_hint.lower() in iface.lower():
            return iface, interfaces

    for iface in interfaces:
        if "vmware" in iface.lower():
            return iface, interfaces

    return interfaces[0], interfaces


def ensure_capture_header(path):
    ensure_parent_dir(path)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()


def append_capture_row(path, row):
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writerow(row)


def ensure_prediction_header(path):
    ensure_parent_dir(path)
    headers = [
        "timestamp",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "frame.len",
        "prediction",
        "attack_confidence",
        "decision",
    ]
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)


def append_prediction(path, row):
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def packet_to_row(packet):
    if IP is None or not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = str(getattr(ip_layer, "src", "") or "")
    dst_ip = str(getattr(ip_layer, "dst", "") or "")
    proto_raw = str(getattr(ip_layer, "proto", 0) or 0)

    src_ip = src_ip.replace("\\", "")
    dst_ip = dst_ip.replace("\\", "")
    if "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()
    if "," in dst_ip:
        dst_ip = dst_ip.split(",")[0].strip()
    if "," in proto_raw:
        proto_raw = proto_raw.split(",")[0].strip()

    try:
        proto_int = int(float(proto_raw))
    except Exception:
        proto_int = 0

    row = {
        "frame.time_epoch": time.time(),
        "packet.registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "ip.proto": proto_int,
        "tcp.srcport": 0,
        "tcp.dstport": 0,
        "udp.srcport": 0,
        "udp.dstport": 0,
        "frame.len": int(len(packet)),
    }

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        row["tcp.srcport"] = int(getattr(tcp_layer, "sport", 0) or 0)
        row["tcp.dstport"] = int(getattr(tcp_layer, "dport", 0) or 0)

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        row["udp.srcport"] = int(getattr(udp_layer, "sport", 0) or 0)
        row["udp.dstport"] = int(getattr(udp_layer, "dport", 0) or 0)

    return row


def build_model_input(row):
    return {
        "frame.time_epoch": row["frame.time_epoch"],
        "ip.src": row["ip.src"],
        "ip.dst": row["ip.dst"],
        "ip.proto": row["ip.proto"],
        "tcp.srcport": row["tcp.srcport"],
        "tcp.dstport": row["tcp.dstport"],
        "udp.srcport": row["udp.srcport"],
        "udp.dstport": row["udp.dstport"],
        "frame.len": row["frame.len"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Capture packets from VMware VMnet on Windows and save to live_data/live_capture.csv"
    )
    parser.add_argument("--iface", default=None, help="Exact interface name or partial name")
    parser.add_argument("--iface-hint", default=DEFAULT_INTERFACE_HINT, help="Preferred interface hint")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("--filter", default="ip", help="BPF filter (default: ip)")
    parser.add_argument("--count", type=int, default=0, help="Packets to capture (0 = continuous)")
    parser.add_argument("--timeout", type=int, default=0, help="Capture timeout in seconds (0 = continuous)")
    parser.add_argument("--output", default=LIVE_CAPTURE_PATH, help="Capture output CSV path")
    parser.add_argument("--model", default=None, help="Optional model path for real-time prediction")
    parser.add_argument("--prediction-log", default=LIVE_PREDICTIONS_PATH, help="Prediction output CSV path")
    parser.add_argument(
        "--alert-threshold",
        type=float,
        default=0.90,
        help="Alert threshold on attack confidence in [0,1] (default: 0.90)",
    )
    args = parser.parse_args()

    args.alert_threshold = max(0.0, min(1.0, args.alert_threshold))

    if "<" in str(args.filter) or ">" in str(args.filter):
        print("❌ Invalid filter placeholder detected.")
        print("Use a real IP instead of <TARGET_IP>.")
        print("Example:")
        print('python src/capture_live_vmnet.py --iface-hint "VMware Network Adapter VMnet1" --filter "ip and host 192.168.47.129" --model models/live_ids_model.pkl')
        return

    if sniff is None:
        print("❌ Scapy not installed. Run: pip install scapy")
        return

    interfaces = list_interfaces()
    if args.list_ifaces:
        if not interfaces:
            print("❌ Could not enumerate interfaces.")
            return
        print("Available interfaces:")
        for iface in interfaces:
            print(f" - {iface}")
        if get_windows_if_list is not None:
            try:
                print("\nWindows interface details:")
                for item in get_windows_if_list():
                    name = item.get("name", "")
                    desc = item.get("description", "")
                    print(f" - {name} | {desc}")
            except Exception:
                pass
        return

    iface, interfaces = resolve_interface(args.iface, args.iface_hint)
    if iface is None:
        print("❌ Could not find a capture interface.")
        print("Try: python src/capture_live_vmnet.py --list-ifaces")
        return

    model = None
    if args.model:
        try:
            import joblib
            import pandas as pd
        except ImportError:
            print("❌ Missing dependencies for model inference. Install: pip install joblib pandas")
            return

        if not os.path.exists(args.model):
            print(f"❌ Model not found: {args.model}")
            return

        model = joblib.load(args.model)
        ensure_prediction_header(args.prediction_log)

    ensure_capture_header(args.output)

    print("=" * 72)
    print("Windows VMnet Live Capture Started")
    print("=" * 72)
    print(f"Interface: {iface}")
    print(f"Filter   : {args.filter}")
    print(f"Output   : {args.output}")
    if model is not None:
        print(f"Model    : {args.model}")
        print(f"Pred log : {args.prediction_log}")
        print(f"Threshold: {args.alert_threshold:.2f}")
    print("Tip      : Run terminal as Administrator if packets do not appear.")
    print("Press Ctrl+C to stop.\n")

    packet_count = 0

    def callback(packet):
        nonlocal packet_count
        row = packet_to_row(packet)
        if row is None:
            return

        append_capture_row(args.output, row)
        packet_count += 1

        summary = (
            f"{row['ip.src']} -> {row['ip.dst']} | proto={row['ip.proto']} "
            f"| tcp={row['tcp.srcport']}->{row['tcp.dstport']} "
            f"| udp={row['udp.srcport']}->{row['udp.dstport']} | len={row['frame.len']}"
        )

        if model is not None:
            import pandas as pd

            x = pd.DataFrame([build_model_input(row)])
            prediction = int(model.predict(x)[0])

            attack_confidence = 0.0
            if hasattr(model, "predict_proba"):
                try:
                    proba = model.predict_proba(x)
                    if proba.shape[1] >= 2:
                        attack_confidence = float(proba[0][1])
                except Exception:
                    attack_confidence = 0.0

            if prediction == 1 and attack_confidence >= args.alert_threshold:
                decision = "CONFIRMED_ALERT"
            elif prediction == 1:
                decision = "SUSPICIOUS_LOW_CONFIDENCE"
            else:
                decision = "NORMAL"

            append_prediction(
                args.prediction_log,
                [
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    row["ip.src"],
                    row["ip.dst"],
                    row["ip.proto"],
                    row["frame.len"],
                    prediction,
                    round(attack_confidence, 4),
                    decision,
                ],
            )

            conf_percent = round(attack_confidence * 100, 2)
            if decision == "CONFIRMED_ALERT":
                print(f"🚨 CONFIRMED ALERT ({conf_percent}%) | {summary}")
            elif decision == "SUSPICIOUS_LOW_CONFIDENCE":
                print(f"⚠️ SUSPICIOUS ({conf_percent}%) | {summary}")
            else:
                print(f"✅ NORMAL ({conf_percent}%) | {summary}")
        else:
            print(summary)

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            prn=callback,
            store=False,
            count=args.count if args.count > 0 else 0,
            timeout=args.timeout if args.timeout > 0 else None,
        )
    except PermissionError:
        print("❌ Permission denied while sniffing. Run PowerShell as Administrator.")
        return
    except OSError as exc:
        print(f"❌ Capture failed: {exc}")
        print("Check Npcap installation and selected interface.")
        if interfaces:
            print("\nDetected interfaces:")
            for item in interfaces:
                print(f" - {item}")
        return
    except Exception as exc:
        print(f"❌ Capture failed: {exc}")
        if "Cannot set filter" in str(exc):
            print("Your BPF filter appears invalid.")
            print("Use a valid filter such as: ip and host 192.168.47.129")
        return
    except KeyboardInterrupt:
        print("\nStopped by user.")

    print(f"\n✅ Capture finished. Packets written: {packet_count}")
    print(f"✅ Packet CSV: {args.output}")
    if model is not None:
        print(f"✅ Prediction log: {args.prediction_log}")


if __name__ == "__main__":
    main()