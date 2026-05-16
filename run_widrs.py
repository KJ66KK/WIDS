import time
import threading
import json
import os
import psutil
import scapy.all as scapy
from scapy.layers.dot11 import Dot11Deauth, Dot11Beacon
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

# =================================================================
# ⚙️ CONFIGURATION SETTINGS
# =================================================================

# 📡 DETECTION THRESHOLDS
# How sensitive should the sniffer be?
DEAUTH_THRESHOLD = 10  # Number of packets to trigger an alert
WINDOW_SECONDS = 5     # Timeframe (in seconds) to count those packets

# 🌐 MQTT SETTINGS (T-Embed Communication)
# Match these to your T-Embed settings in Bruce Firmware
MQTT_BROKER = "localhost" # Set to "localhost" if Mosquitto is on this PC
MQTT_PORT = 1883           # Default Mosquitto port
MQTT_TOPIC = "widrs/alerts" # The topic Bruce publishes to

# =================================================================

console = Console()
packet_counts = {} # Stores MAC -> [timestamps] for flood detection
stop_event = threading.Event()

# --- UTILS: Network & Interface ---

def get_wifi_interface():
    """
    Automatically finds your active WiFi interface.
    It looks for common names (Wi-Fi, wlan0) and ensures the interface
    is currently UP and has an assigned IP address.
    """
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    wifi_prefixes = ('wi-fi', 'wlan', 'wlp', 'wifi')
    
    # Check for specifically named WiFi adapters first
    for iface, iface_addrs in addrs.items():
        if any(prefix in iface.lower() for prefix in wifi_prefixes):
            if iface in stats and stats[iface].isup:
                if any(addr.family == 2 for addr in iface_addrs): # Check for IPv4
                    return iface
    
    # Fallback: find any active interface that isn't a loopback
    for iface, iface_addrs in addrs.items():
        if iface == 'lo' or iface.startswith('Loopback'):
            continue
        if iface in stats and stats[iface].isup:
            if any(addr.family == 2 for addr in iface_addrs):
                return iface
    return None

def log_alert(event_type, source_mac, details, signal=None):
    """Saves a detected threat directly into the local SQLite database."""
    db = SessionLocal()
    try:
        db_alert = models.Alert(
            event_type=event_type,
            source_mac=source_mac,
            signal_strength=signal,
            details=details
        )
        db.add(db_alert)
        db.commit()
    finally:
        db.close()

# --- DETECTION: Packet Sniffing ---

def packet_callback(packet):
    """
    Analyzes every captured packet.
    If it's a Deauthentication frame, we track it for flood detection.
    """
    if packet.haslayer(Dot11Deauth):
        source_mac = packet.addr2 # The MAC of the sender
        now = time.time()
        
        if source_mac not in packet_counts:
            packet_counts[source_mac] = []
        
        packet_counts[source_mac].append(now)
        
        # Keep only packets from the last X seconds
        packet_counts[source_mac] = [t for t in packet_counts[source_mac] if now - t < WINDOW_SECONDS]
        
        # If the count exceeds threshold, log a flood alert
        if len(packet_counts[source_mac]) >= DEAUTH_THRESHOLD:
            log_alert(
                "DEAUTH_FLOOD", 
                source_mac, 
                {"packet_count": len(packet_counts[source_mac]), "msg": "Deauth flood detected via local sniffer"},
                signal=getattr(packet, "dBm_AntSignal", None) # Signal strength if available
            )
            packet_counts[source_mac] = [] # Reset to avoid spamming alerts

def start_sniffer(interface):
    """Runs the Scapy sniffer in a background thread."""
    try:
        scapy.sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
    except Exception as e:
        console.print(f"[bold red]Sniffer Error:[/] {e}")

# --- BRIDGE: T-Embed MQTT ---

def on_message(client, userdata, msg):
    """Handles alerts sent from the T-Embed hardware via MQTT."""
    try:
        payload = json.loads(msg.payload.decode())
        log_alert(
            payload.get("event", "HARDWARE_ALERT"),
            payload.get("mac", "UNKNOWN"),
            payload.get("details", payload),
            payload.get("signal")
        )
    except Exception as e:
        pass

def start_mqtt():
    """Connects to the Mosquitto broker to receive hardware alerts."""
    client = mqtt.Client()
    client.on_message = on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.subscribe(MQTT_TOPIC)
        console.print("[bold green]✓ MQTT Bridge Connected.[/]")
        client.loop_forever()
    except Exception:
        console.print("[bold red]MQTT Error:[/] Could not connect to Mosquitto. Hardware alerts are disabled.")

# --- UI: Terminal Dashboard ---

def generate_table():
    """Queries the database and builds the Rich table for the dashboard."""
    db = SessionLocal()
    alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(10).all()
    db.close()

    table = Table(title="Live Wireless Intrusion Events", box=box.ROUNDED, expand=True)
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Type", style="bold red")
    table.add_column("Source MAC", style="green")
    table.add_column("Signal", style="magenta")
    table.add_column("Details", style="white")

    for alert in alerts:
        table.add_row(
            alert.timestamp.strftime("%H:%M:%S"),
            alert.event_type,
            alert.source_mac,
            f"{alert.signal_strength or 'N/A'} dBm",
            str(alert.details)[:50]
        )
    return table

def inject_test_alert():
    """Utility to verify the UI is working without needing an actual attack."""
    log_alert("SYSTEM_TEST", "AA:BB:CC:DD:EE:FF", {"msg": "Self-test alert triggered!"})
    console.print("[bold green]✓ Test alert injected into database.[/]")

# --- MAIN ENGINE ---

def main():
    # Setup the local database
    init_db()
    
    # Handle manual test mode: 'python run_widrs.py --test'
    import sys
    if "--test" in sys.argv:
        inject_test_alert()
        return

    console.print("[bold cyan]WIDRS Engine Starting...[/]")
    
    # 1. Automatic Interface Detection
    with console.status("[bold yellow]Detecting active WiFi interface...", spinner="dots"):
        iface = get_wifi_interface()
        time.sleep(1)
        
    if not iface:
        console.print("[bold red]Error: No active WiFi interface detected![/]")
        console.print("[yellow]Please connect to a network and try again.[/]")
        return
    
    console.print(f"[bold green]✓ Found active interface:[/] [bold white]{iface}[/]")

    # 2. Start background tasks (Sniffer and MQTT Bridge)
    threading.Thread(target=start_sniffer, args=(iface,), daemon=True).start()
    threading.Thread(target=start_mqtt, daemon=True).start()

    # 3. Launch the Live Dashboard
    with Live(console=console, screen=True, refresh_per_second=1) as live:
        try:
            while True:
                db = SessionLocal()
                total = db.query(models.Alert).count()
                db.close()

                # Build the layout
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="body")
                )
                
                header_content = f"🛡️  [bold blue]WIDRS CLI[/] | [bold white]Interface:[/] {iface} | [bold white]Total Alerts:[/] {total}"
                layout["header"].update(Panel(header_content, border_style="blue"))
                layout["body"].update(generate_table())
                
                live.update(layout)
                time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()
            console.print("\n[bold yellow]Stopping WIDRS...[/]")

if __name__ == "__main__":
    main()
