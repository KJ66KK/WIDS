# Wireless Intrusion Detection & Response System (WIDRS) 🛡️

WIDRS is a professional-grade terminal security tool designed to detect wireless threats in real-time. It provides a unified dashboard that combines local packet sniffing with remote telemetry from hardware devices like the **LilyGO T-Embed**, **Flipper Zero**, or **ESP32** sensors.

## ✨ Key Features
- **All-in-One CLI:** No local web servers or complex brokers required.
- **Universal Cloud Bridge:** Uses HiveMQ Public Broker for zero-config hardware alerts.
- **Auto-Network Detection:** Automatically identifies your active WiFi interface.
- **Hybrid Monitoring:** Captures local packet anomalies (Scapy) and hardware-triggered events.
- **Persistent Logging:** Saves all security events to a local SQLite database for forensics.
- **Real-time Dashboard:** High-performance terminal UI powered by `Rich`.

## 🚀 Quick Start

### 1. Requirements
- Python 3.11+
- **[Npcap](https://npcap.com/) (Required for Windows):** During installation, ensure you check *"Support raw 802.11 packet capturing"*.
- **External Hardware (Recommended):** To get the most out of WIDRS, you need an external device to act as a remote sensor or attacker (see below).

### 2. Setup
```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/WIDS.git
cd WIDS

# Install as a command-line tool
pip install -e .
```

### 3. Run
```bash
# Get help
wids -h

# Start monitoring
wids
```

---

## 🛰️ Hardware Requirements
WIDRS is designed to work as a "Command Center" for your security hardware. While the PC sniffer can detect some activity, many PC WiFi cards are "blind" to management packets. For full detection, you should use one of the following:

### 1. LilyGO T-Embed (Recommended)
- **Firmware:** [Bruce Firmware](https://github.com/pr3y/Bruce)
- **Function:** Acts as a portable attacker/sensor.
- **Config:** Set MQTT Server to `broker.hivemq.com` and Topic to `widrs/alerts/global_test`.

### 2. Flipper Zero
- **Function:** Can trigger deauth attacks or scan for sub-GHz signals.
- **Integration:** Use a WiFi Devboard (ESP32) running a script that sends JSON reports to the Cloud Bridge.

### 3. Custom ESP32 / ESP8266
- Any ESP-based board can be programmed to act as a "distributed sensor" that reports local traffic anomalies to your WIDS dashboard via MQTT.

---

## 🧠 How it Works
1. **The Engine:** `wids` launches parallel threads for local sniffing and a Cloud Bridge listener.
2. **The Cloud Bridge:** Hardware devices send JSON reports to a public broker (`broker.hivemq.com`). Your PC "subscribes" to these alerts instantly, removing the need for local Mosquitto setup.
3. **Anomaly Detection:** The tool monitors your PC's WiFi card for massive surges in packet volume, allowing it to flag attacks even if the specific packet type is hidden by Windows.
4. **Forensics:** Every alert is logged to `widrs.db` with a timestamp, MAC address, and event type.

## 🚧 Roadmap
- [x] All-in-One Terminal UI
- [x] Universal Cloud Bridge
- [x] Auto-Interface Detection
- [ ] PCAP export for threat forensics
- [ ] Rogue AP (Evil Twin) detection logic
- [ ] Discord/Telegram notification webhooks
