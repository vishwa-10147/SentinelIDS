# src/vendor_lookup.py

import os
import pandas as pd

OUI_DB_PATH = "datasets/oui/oui_db.csv"

def load_oui_db():
    """
    Loads OUI database from datasets/oui/oui_db.csv
    Must contain columns: prefix, vendor
    Example:
        prefix = "04:70:56"
        vendor = "Xiaomi Communications Co Ltd"
    """
    if not os.path.exists(OUI_DB_PATH):
        return pd.DataFrame(columns=["prefix", "vendor"])

    try:
        df = pd.read_csv(OUI_DB_PATH)
        if "prefix" not in df.columns or "vendor" not in df.columns:
            return pd.DataFrame(columns=["prefix", "vendor"])
        df["prefix"] = df["prefix"].astype(str).str.upper().str.strip()
        df["vendor"] = df["vendor"].astype(str).str.strip()
        return df
    except Exception:
        return pd.DataFrame(columns=["prefix", "vendor"])


def normalize_mac(mac: str) -> str:
    """
    Normalize mac into format XX:XX:XX:XX:XX:XX
    """
    if mac is None:
        return ""
    mac = str(mac).strip().upper()

    # Replace separators
    mac = mac.replace("-", ":").replace(".", ":")

    # If format is like 0470.56EA.2489 -> make it 04:70:56:EA:24:89
    if len(mac) == 14 and "." in mac:
        mac = mac.replace(".", "")
        mac = ":".join([mac[i:i+2] for i in range(0, 12, 2)])

    return mac


def get_oui_prefix(mac: str) -> str:
    """
    OUI prefix = first 3 bytes -> XX:XX:XX
    """
    mac = normalize_mac(mac)
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])


def lookup_vendor(mac: str, oui_df=None) -> str:
    """
    Returns vendor name using OUI prefix lookup.
    """
    if oui_df is None:
        oui_df = load_oui_db()

    prefix = get_oui_prefix(mac)
    if prefix == "":
        return "Unknown"

    match = oui_df[oui_df["prefix"] == prefix]
    if match.empty:
        return "Unknown"

    return str(match.iloc[0]["vendor"])
