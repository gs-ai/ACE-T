# backend/app/schemas/schemas.py
from pydantic import BaseModel
from datetime import datetime

# Schema for reading a user
class User(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True  # For Pydantic v2

# Schema for creating a user
class UserCreate(BaseModel):
    name: str
    email: str

# Schema for updating a user
class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None

    class Config:
        from_attributes = True

class OSINTRecordBase(BaseModel):
    source: str
    content: str
    tags: str | None = None

class OSINTRecordCreate(OSINTRecordBase):
    pass

class OSINTRecord(OSINTRecordBase):
    id: int
    timestamp: datetime
    class Config:
        from_attributes = True
