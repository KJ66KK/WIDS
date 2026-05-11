# 🛡️ Wireless Intrusion Detection & Response System (WIDRS)

WIDRS is a lightweight SOC sensor for wireless threats, utilizing the T-Embed CC1101 (Bruce firmware) as a sensor node and a Python-based backend for detection and analysis.

## 🏗️ Project Structure

- `backend/`: FastAPI server, detection engine, and database logic.
- `firmware/`: Scripts and documentation for the T-Embed CC1101.
- `dashboard/`: Frontend for live monitoring and alerts.
- `docs/`: Project documentation.
- `pcaps/`: Captured suspicious wireless traffic.

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.8+
- MQTT Broker (e.g., Mosquitto)
- T-Embed CC1101 with Bruce Firmware

### 2. Setup
1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 3. Running the System
1. Start the FastAPI Backend:
   ```bash
   python backend/main.py
   ```
2. Start the MQTT Subscriber:
   ```bash
   python backend/mqtt_subscriber.py
   ```

## 🛡️ Key Features (Roadmap)
- [ ] Deauthentication Attack Detection
- [ ] Rogue Access Point (AP) Detection
- [ ] Nearby Device Discovery
- [ ] Threat Scoring Dashboard
- [ ] PCAP Export for Incident Response
