import os
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

LIVE_LOG_PATH = "logs/live_detections.csv"
INCIDENTS_LOG_PATH = "logs/incidents.csv"
OUTPUT_DIR = "reports"

def safe_read_csv(path):
    try:
        if os.path.exists(path):
            # If file is empty (0 bytes), return empty DataFrame
            if os.path.getsize(path) == 0:
                return pd.DataFrame()
            return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()
    return pd.DataFrame()


def generate_pdf():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(OUTPUT_DIR, f"IoT_IDS_Report_{ts}.pdf")

    live_df = safe_read_csv(LIVE_LOG_PATH)
    incidents_df = safe_read_csv(INCIDENTS_LOG_PATH)

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "IoT Intrusion Detection System (ML-Based) रिपोर्ट")

    c.setFont("Helvetica", 11)
    c.drawString(50, height - 70, f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y = height - 110

    # Summary
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "1) Live Traffic Summary")
    y -= 25

    if live_df.empty:
        c.setFont("Helvetica", 11)
        c.drawString(50, y, "No live detection data found (logs/live_detections.csv missing).")
        c.save()
        return pdf_path

    total_packets = len(live_df)
    suspicious_packets = int((live_df["prediction"] == 1).sum()) if "prediction" in live_df.columns else 0
    high_risk_packets = int((live_df.get("risk_score_%", 0) >= 80).sum()) if "risk_score_%" in live_df.columns else 0

    c.setFont("Helvetica", 11)
    c.drawString(60, y, f"Total Packets Analyzed: {total_packets}")
    y -= 18
    c.drawString(60, y, f"Suspicious Packets: {suspicious_packets}")
    y -= 18
    c.drawString(60, y, f"High Risk Packets (>=80% risk): {high_risk_packets}")
    y -= 25

    # Incidents
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "2) Incident Timeline (Last 10)")
    y -= 20

    c.setFont("Helvetica", 10)
    if incidents_df.empty:
        c.drawString(60, y, "No incidents logged yet.")
        y -= 15
    else:
        last10 = incidents_df.tail(10)
        for _, row in last10.iterrows():
            line = f"{row.get('timestamp')} | {row.get('incident_id')} | {row.get('severity')} | Susp={row.get('suspicious_packets')} | HighRisk={row.get('high_risk_packets')} | TopIP={row.get('top_suspicious_src_ip')}"
            c.drawString(60, y, line[:110])
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)

    y -= 10

    # Device Inventory (Top 10)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "3) Top Devices (Inventory - Top 10)")
    y -= 20

    c.setFont("Helvetica", 10)
    if "ip.src" in live_df.columns:
        live_df["is_suspicious"] = (live_df["prediction"] == 1).astype(int)

        device_summary = live_df.groupby("ip.src").agg(
            total=("ip.src", "count"),
            suspicious=("is_suspicious", "sum"),
            avg_risk=("risk_score_%", "mean") if "risk_score_%" in live_df.columns else ("is_suspicious", "mean")
        ).reset_index()

        device_summary["suspicious_%"] = (device_summary["suspicious"] / device_summary["total"] * 100).round(2)
        device_summary = device_summary.sort_values(["suspicious", "total"], ascending=False).head(10)

        for _, row in device_summary.iterrows():
            line = f"{row['ip.src']} | Total={row['total']} | Susp={row['suspicious']} | Susp%={row['suspicious_%']} | AvgRisk={round(row['avg_risk'],2)}"
            c.drawString(60, y, line[:110])
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)
    else:
        c.drawString(60, y, "Device inventory not available (missing ip.src).")
        y -= 15

    y -= 10

    # Top suspicious source IPs
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "4) Top Suspicious Source IPs (Top 10)")
    y -= 20

    c.setFont("Helvetica", 10)
    suspicious_only = live_df[live_df["prediction"] == 1] if "prediction" in live_df.columns else pd.DataFrame()
    if suspicious_only.empty:
        c.drawString(60, y, "No suspicious packets found.")
        y -= 15
    else:
        top_src = suspicious_only["ip.src"].value_counts().head(10)
        for ip, count in top_src.items():
            c.drawString(60, y, f"{ip}  ->  {count} packets")
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)

    y -= 10

    # Top 5 high-risk packets
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "5) Top 5 High-Risk Packets")
    y -= 20

    c.setFont("Helvetica", 10)
    if "risk_score_%" in live_df.columns:
        top_risk = live_df.sort_values("risk_score_%", ascending=False).head(5)
        for _, row in top_risk.iterrows():
            line = f"Src={row.get('ip.src')} -> Dst={row.get('ip.dst')} | Len={row.get('frame.len')} | Risk={row.get('risk_score_%')}% | Pred={row.get('prediction_label')}"
            c.drawString(60, y, line[:110])
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 60
                c.setFont("Helvetica", 10)
    else:
        c.drawString(60, y, "Risk score not available.")
        y -= 15

    y -= 10

    # Footer
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 40, "Report generated by IoT IDS Dashboard (Mini Project).")

    c.save()
    return pdf_path


if __name__ == "__main__":
    path = generate_pdf()
    print("✅ PDF Generated:", path)
