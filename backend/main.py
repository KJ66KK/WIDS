from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import datetime

app = FastAPI(title="WIDRS Backend", description="Wireless Intrusion Detection & Response System API")

class WirelessAlert(BaseModel):
    event_type: str
    source_mac: str
    signal_strength: int
    timestamp: datetime.datetime = datetime.datetime.now()
    details: Optional[dict] = None

@app.get("/")
async def root():
    return {"message": "WIDRS API is running"}

@app.get("/status")
async def get_status():
    return {
        "status": "online",
        "sensors_connected": 0,
        "last_alert": None
    }

@app.post("/alerts")
async def create_alert(alert: WirelessAlert):
    # This will later save to the database and trigger notifications
    print(f"Received Alert: {alert.event_type} from {alert.source_mac}")
    return {"status": "received", "alert_id": "placeholder-uuid"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
