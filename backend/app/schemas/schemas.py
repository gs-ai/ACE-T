from pydantic import BaseModel
from datetime import datetime

# Schema for reading a user
class User(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True  # This replaces orm_mode in Pydantic v2

# Schema for creating a user
class UserCreate(BaseModel):
    name: str
    email: str

# Schema for updating a user
class UserUpdate(BaseModel):
    name: str
    email: str

    class Config:
        from_attributes = True
