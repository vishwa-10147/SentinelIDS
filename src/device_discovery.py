import os
import pandas as pd
from datetime import datetime

from src.vendor_lookup import lookup_vendor, load_oui_db
from src.hostname_lookup import get_hostname_from_ip

ARP_FILE = "logs/arp_table_kali.csv"
OUT_FILE = "logs/device_inventory.csv"


def main():
    if not os.path.exists(ARP_FILE):
        print("[ERROR] arp_table_kali.csv not found inside logs/")
        print("  -> First export ARP scan from Kali to shared folder.")
        return

    # Check if file is empty
    if os.path.getsize(ARP_FILE) == 0:
        print("[ERROR] arp_table_kali.csv is EMPTY (0 bytes)!")
        print("")
        print("  -> Run these commands in Kali to fix:")
        print("")
        print("  sudo arp-scan --localnet | awk '/^192\\./ {print $1\",\"$2}' > /tmp/arp_table_kali.csv")
        print("  cat /tmp/arp_table_kali.csv")
        print("  cp /tmp/arp_table_kali.csv /mnt/hgfs/live_data/arp_table_kali.csv")
        print("")
        print("  -> Then on Windows run:")
        print("  copy live_data\\arp_table_kali.csv logs\\arp_table_kali.csv")
        return

    try:
        df = pd.read_csv(ARP_FILE, header=None)
    except pd.errors.EmptyDataError:
        print("[ERROR] arp_table_kali.csv has no readable CSV data!")
        print("")
        print("  -> Run these commands in Kali to fix:")
        print("")
        print("  sudo arp-scan --localnet | awk '/^192\\./ {print $1\",\"$2}' > /tmp/arp_table_kali.csv")
        print("  cat /tmp/arp_table_kali.csv")
        print("  cp /tmp/arp_table_kali.csv /mnt/hgfs/live_data/arp_table_kali.csv")
        print("")
        print("  -> Then on Windows run:")
        print("  copy live_data\\arp_table_kali.csv logs\\arp_table_kali.csv")
        return

    # Fix: if CSV has wrong columns
    if df.shape[1] == 2:
        df.columns = ["ip", "mac"]
    elif df.shape[1] > 2:
        # Take first 2 columns only (IP and MAC)
        df = df.iloc[:, :2]
        df.columns = ["ip", "mac"]
    else:
        print("[ERROR] arp_table_kali.csv must contain at least 2 columns: ip, mac")
        print(f"   Found {df.shape[1]} column(s)")
        return
    
    # Remove any empty rows
    df = df.dropna(subset=["ip", "mac"])
    if df.empty:
        print("[ERROR] arp_table_kali.csv has no valid IP,MAC entries!")
        return

    df["ip"] = df["ip"].astype(str).str.strip()
    df["mac"] = df["mac"].astype(str).str.strip()

    # Remove bad header row accidentally included
    df = df[df["ip"].str.lower() != "ip"]
    df = df[df["mac"].str.lower() != "mac"]

    # Keep only IPv4 addresses (ignore IPv6)
    df = df[df["ip"].str.contains(r"^\d+\.\d+\.\d+\.\d+$", regex=True)]

    # Remove duplicate IPs (keep last occurrence)
    df = df.drop_duplicates(subset=["ip"], keep="last")

    if df.empty:
        print("[ERROR] No valid IPv4 addresses found after cleaning!")
        return

    # Load vendor db
    oui_db = load_oui_db()

    # Add vendor + hostname
    df["vendor"] = df["mac"].apply(lambda mac: lookup_vendor(mac, oui_db))
    df["hostname"] = df["ip"].apply(get_hostname_from_ip)

    # Time fields
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    df["first_seen"] = now
    df["last_seen"] = now

    # Merge with existing inventory (if exists)
    if os.path.exists(OUT_FILE):
        old = pd.read_csv(OUT_FILE)

        combined = pd.concat([old, df], ignore_index=True)

        # Keep latest last_seen per IP
        combined["last_seen"] = now

        combined = combined.drop_duplicates(subset=["ip"], keep="last")
        combined.to_csv(OUT_FILE, index=False)
    else:
        df.to_csv(OUT_FILE, index=False)

    print("[OK] Device inventory updated!")
    print(f"Saved: {OUT_FILE}")
    print(df.head(10))


if __name__ == "__main__":
    main()
