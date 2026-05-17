import time
import threading
import json
import os
import psutil
import socket
import scapy.all as scapy
from scapy.layers.dot11 import Dot11Deauth, Dot11Beacon, Dot11
from scapy.layers.inet import IP
import paho.mqtt.client as mqtt
from sqlalchemy.orm import Session
from backend.database import models
from backend.database.models import SessionLocal, init_db
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box
import datetime
import uuid
import argparse
import sys

# =================================================================
# ⚙️ CONFIGURATION SETTINGS
# =================================================================

# 📡 DETECTION THRESHOLDS
DEAUTH_THRESHOLD = 5   # Low for testing
ANOMALY_THRESHOLD = 300 # Flag ANY MAC sending > 200 packets in 5s
WINDOW_SECONDS = 5     

# ☁️ UNIVERSAL CLOUD BRIDGE
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_TOPIC = "widrs/alerts/global_test" 

# =================================================================

console = Console()
packet_counts = {} 
anomaly_counts = {} # Tracks total packets per MAC (for blind Windows cards)
stop_event = threading.Event()
mqtt_status = "Connecting..."

# --- UTILS ---

def log_alert(event_type, source_mac, details, signal=None, source_ip=None):
    """Saves a detected threat directly into the local SQLite database."""
    db = SessionLocal()
    try:
        db_alert = models.Alert(
            event_type=event_type, source_mac=source_mac,
            source_ip=source_ip,
            signal_strength=signal, details=details
        )
        db.add(db_alert)
        db.commit()
    finally:
        db.close()

# --- DETECTION: Enhanced Engine ---

def packet_callback(packet):
    """
    Enhanced callback that catches attacks even if the Windows card 
    is 'blind' to specific WiFi management frames.
    """
    now = time.time()
    source_mac = "UNKNOWN"
    source_ip = None
    
    # Try to extract the MAC address
    if packet.haslayer(Dot11):
        source_mac = packet.addr2 if packet.addr2 else "UNKNOWN"
    elif hasattr(packet, 'src'):
        source_mac = packet.src

    # Try to extract the IP address if it exists
    if packet.haslayer(IP):
        source_ip = packet[IP].src

    if source_mac == "UNKNOWN" and not source_ip: return

    # 1. SPECIFIC DETECTION: Deauth Frames
    if packet.haslayer(Dot11Deauth):
        if source_mac not in packet_counts: packet_counts[source_mac] = []
        packet_counts[source_mac].append(now)
        packet_counts[source_mac] = [t for t in packet_counts[source_mac] if now - t < WINDOW_SECONDS]
        
        if len(packet_counts[source_mac]) >= DEAUTH_THRESHOLD:
            log_alert("DEAUTH_ATTACK", source_mac, {"msg": "Direct Deauth detected!"}, source_ip=source_ip)
            packet_counts[source_mac] = []

    # 2. ANOMALY DETECTION: Packet Volume
    if source_mac not in anomaly_counts: anomaly_counts[source_mac] = []
    anomaly_counts[source_mac].append(now)
    anomaly_counts[source_mac] = [t for t in anomaly_counts[source_mac] if now - t < WINDOW_SECONDS]

    if len(anomaly_counts[source_mac]) >= ANOMALY_THRESHOLD:
        log_alert(
            "TRAFFIC_ANOMALY", 
            source_mac, 
            {"packet_count": len(anomaly_counts[source_mac]), "msg": "High-volume RF activity detected!"},
            source_ip=source_ip
        )
        anomaly_counts[source_mac] = []

def start_sniffer(interface):
    is_windows = os.name == 'nt'
    try:
        scapy.sniff(
            iface=interface, prn=packet_callback, store=0, 
            monitor=not is_windows, 
            stop_filter=lambda x: stop_event.is_set()
        )
    except Exception:
        try:
            scapy.sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
        except Exception as e:
            console.print(f"[bold red]Sniffer Error:[/] {e}")

# --- BRIDGE ---

def on_connect(client, userdata, flags, rc):
    global mqtt_status
    if rc == 0: mqtt_status = "Online (HiveMQ)"
    else: mqtt_status = f"Error ({rc})"

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        log_alert(
            payload.get("event", "CLOUD_REPORT"),
            payload.get("mac", "UNKNOWN"),
            payload.get("details", payload),
            source_ip=payload.get("ip")
        )
    except Exception: pass

def start_mqtt_bridge():
    global mqtt_status
    client_id = f"widrs-{uuid.uuid4().hex[:6]}"
    # Use modern Callback API version 2
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.subscribe(MQTT_TOPIC)
        client.loop_forever()
    except Exception:
        mqtt_status = "Disconnected"

# --- UI ---

def generate_table():
    db = SessionLocal()
    alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(10).all()
    db.close()
    table = Table(box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    table.add_column("Time", style="cyan", width=10)
    table.add_column("Threat Type", style="bold red")
    table.add_column("Source MAC", style="green")
    table.add_column("Source IP", style="yellow")
    table.add_column("Details", style="white")

    for alert in alerts:
        table.add_row(
            alert.timestamp.strftime("%H:%M:%S"),
            alert.event_type,
            alert.source_mac,
            alert.source_ip or "---",
            str(alert.details.get('msg', alert.details))[:60]
        )
    return table

def reset_db():
    """Clears all alerts from the database for a fresh start"""
    db = SessionLocal()
    try:
        db.query(models.Alert).delete()
        db.commit()
        console.print("[bold green]✓ Alert history cleared![/]")
    except Exception as e:
        console.print(f"[bold red]Error clearing database:[/] {e}")
    finally:
        db.close()

# --- MAIN RUNNER ---

def main():
    """Main entry point for the WIDRS CLI"""
    # CRITICAL: The global declaration MUST be the absolute first line
    global ANOMALY_THRESHOLD
    
    init_db()
    
    # --- COMMAND LINE ARGUMENTS ---
    parser = argparse.ArgumentParser(
        description="🛡️ WIDRS: Wireless Intrusion Detection & Response System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_widrs.py           # Start the live monitoring sensor
  python run_widrs.py --test    # Inject a fake alert to test the UI
  python run_widrs.py --reset   # Clear all alert history from the database
        """
    )
    
    parser.add_argument("--test", action="store_true", help="Inject a test alert into the database and exit")
    parser.add_argument("--reset", action="store_true", help="Clear all stored alerts from the local database")
    parser.add_argument("--threshold", type=int, default=ANOMALY_THRESHOLD, help=f"Set custom anomaly threshold (default: {ANOMALY_THRESHOLD})")
    
    # If no arguments are provided, it proceeds to start the engine
    args, unknown = parser.parse_known_args()

    # Handle --reset
    if args.reset:
        reset_db()
        return

    # Handle --test
    if args.test:
        log_alert("TEST_ALERT", "FF:FF:FF:FF:FF:FF", {"msg": "System self-test successful!"})
        console.print("[bold green]✓ Test alert injected into database.[/]")
        return

    # Update threshold if provided
    ANOMALY_THRESHOLD = args.threshold

    # --- START ENGINE ---
    console.print("[bold cyan]WIDRS Engine Starting...[/]")
    
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    iface = None
    ip_address = "Offline"
    
    # Auto-detect WiFi interface and IP
    wifi_prefixes = ('wi-fi', 'wlan', 'wlp', 'wifi', 'en')
    for i, i_addrs in addrs.items():
        if any(prefix in i.lower() for prefix in wifi_prefixes) and i in stats and stats[i].isup:
            for addr in i_addrs:
                if addr.family == 2: # AF_INET
                    iface = i
                    ip_address = addr.address
                    break
        if iface: break
    
    if iface:
        console.print(f"[bold green]✓ PC Sniffer Active:[/] {iface} ({ip_address})")
        threading.Thread(target=start_sniffer, args=(iface,), daemon=True).start()
    else:
        console.print("[bold yellow]! No WiFi interface detected. Sniffer disabled (Cloud Bridge remains active).[/]")

    # Start Cloud Bridge
    threading.Thread(target=start_mqtt_bridge, daemon=True).start()

    with Live(console=console, screen=True, refresh_per_second=2) as live:
        try:
            while True:
                db = SessionLocal()
                total = db.query(models.Alert).count()
                db.close()
                
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="body")
                )
                
                # Show Interface and IP in the header
                status_line = f"🛡️  [bold white]WIDRS SENSOR[/]  |  [bold cyan]Cloud:[/] {mqtt_status}  |  [bold green]IP:[/] {ip_address}  |  [bold cyan]Alerts:[/] {total}"
                layout["header"].update(Panel(status_line, border_style="blue"))
                layout["body"].update(generate_table())
                live.update(layout)
                time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

if __name__ == "__main__":
    main()
