import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth
import psutil
import time

def get_wifi_interface():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    wifi_prefixes = ('wi-fi', 'wlan', 'wlp', 'wifi')
    for iface in stats:
        if any(prefix in iface.lower() for prefix in wifi_prefixes):
            if stats[iface].isup:
                return iface
    return None

def debug_callback(packet):
    if packet.haslayer(Dot11):
        # If we see ANY Dot11 layer, the card is at least partially working in monitor mode
        if packet.haslayer(Dot11Beacon):
            print(f"📡 [BEACON] Seen from SSID: {packet.info.decode('utf-8', 'ignore')} (MAC: {packet.addr2})")
        elif packet.haslayer(Dot11Deauth):
            print(f"🛑 [DEAUTH] !!! ATTACK DETECTED !!! From: {packet.addr2} To: {packet.addr1}")
        else:
            print(f"📦 [PACKET] Type: {packet.type} Subtype: {packet.subtype} From: {packet.addr2}")
    else:
        # This means we are only seeing standard Ethernet/IP traffic (blind to WiFi frames)
        if not hasattr(debug_callback, 'warned'):
            print("⚠️ Only seeing standard data (IP/TCP/UDP). Your WiFi card is BLIND to management frames.")
            debug_callback.warned = True

def run_diagnostic():
    iface = get_wifi_interface()
    if not iface:
        print("❌ No WiFi interface found.")
        return

    print(f"🔍 Starting Deep Diagnostic on: {iface}")
    print("--------------------------------------------------")
    print("STEP 1: Checking for Beacon frames (Normal WiFi background noise)")
    print("If you don't see BEACON lines below, your card/driver is blocking security scans.")
    print("--------------------------------------------------")
    
    try:
        # On Windows, monitor=True is often required but frequently fails.
        # We try without it first as Npcap often handles the 'translation'
        scapy.sniff(iface=iface, prn=debug_callback, store=0, timeout=15)
    except Exception as e:
        print(f"❌ Sniff Error: {e}")

if __name__ == "__main__":
    run_diagnostic()
