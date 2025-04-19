# backend/app/models/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from backend.app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class OSINTRecord(Base):
    __tablename__ = "osint_records"
    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    tags = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
