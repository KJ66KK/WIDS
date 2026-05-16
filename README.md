# Wireless Intrusion Detection & Response System (WIDRS) 🛡️

WIDRS is a professional-grade terminal security tool designed to detect wireless threats in real-time. It monitors for deauthentication attacks and integrates with the LilyGO T-Embed (Bruce Firmware) to provide hardware-based security telemetry.

## ✨ Key Features
- **All-in-One CLI:** No web servers, browsers, or external dependencies required.
- **Auto-Network Detection:** Automatically identifies your active WiFi interface.
- **Hybrid Monitoring:** Combines local packet sniffing (Scapy) with IoT hardware alerts (MQTT).
- **Persistent Logging:** Saves all security events to a local SQLite database for forensics.
- **Real-time Dashboard:** Beautifully formatted terminal UI using `Rich`.

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+
- **[Mosquitto MQTT Broker](https://mosquitto.org/download/) (MANDATORY):** This handles the communication between your T-Embed and the Python script.
- **[Npcap](https://npcap.com/) (Required for Scapy on Windows):** Ensure you check *"Support raw 802.11 packet capturing"* during install.

### 2. Setup
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/WIDS.git
cd WIDS

# Install dependencies
pip install -r requirements.txt
```

### 3. Run
```bash
# Run as Administrator/sudo for packet sniffing permissions
python run_widrs.py
```

## 🧠 How it Works
1. **Unified Engine:** `run_widrs.py` is the single entry point. It launches parallel threads for:
   - **Sniffer:** Monitors 802.11 management frames for flood attacks.
   - **MQTT Bridge:** Listens for alerts from your T-Embed hardware via the **Mosquitto broker**.
   - **Live UI:** A high-performance terminal dashboard.
2. **Auto-Detect:** The system uses `psutil` to scan your network adapters and identify your active WiFi connection automatically.
3. **Database:** All security events are logged to `widrs.db` via SQLAlchemy.

## 🛡️ T-Embed Integration
- Flash **Bruce Firmware** to your T-Embed.
- Ensure the **Mosquitto** service is running on your PC (`net start mosquitto`).
- Configure the T-Embed's MQTT settings to point to your PC's IP address.
- Hardware-triggered events (like RF scans or NFC clones) will appear instantly in your CLI dashboard.

## 🚧 Roadmap
- [x] All-in-One Terminal UI
- [x] Auto-Interface Detection
- [x] Local SQLite persistence
- [ ] PCAP export for threat forensics
- [ ] Rogue AP (Evil Twin) detection logic
- [ ] Discord/Telegram notification webhooks
