# backend/app/schemas/schemas.py
from pydantic import BaseModel, Field
from datetime import datetime

# Base schema for shared fields
class UserBase(BaseModel):
    name: str
    email: str

# Schema for creating a user
class UserCreate(UserBase):
    pass

# Schema for returning full user data
class User(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True  # Updated for Pydantic V2
