from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# --- DATABASE CONFIGURATION ---
# SQLite is used here for its simplicity (it's just a file on your disk)
SQLALCHEMY_DATABASE_URL = "sqlite:///./widrs.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# --- DATABASE MODELS ---
# This class defines the 'alerts' table in your database
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String)      # Type of attack (e.g., DEAUTH)
    source_mac = Column(String)      # MAC address of the attacker
    signal_strength = Column(Integer, nullable=True) # How close they are (RSSI)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow) # When it happened
    details = Column(JSON, nullable=True) # Flexible field for extra data (SSID, counts, etc.)

def init_db():
    """Creates the tables defined above if they don't already exist"""
    Base.metadata.create_all(bind=engine)
