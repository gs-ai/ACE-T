# backend/app/crud.py
from sqlalchemy.orm import Session
from backend.app.models.models import User, OSINTRecord
from backend.app.schemas.schemas import UserCreate, UserUpdate, OSINTRecordCreate

# Function to create a user
def create_user(db: Session, user: UserCreate):
    db_user = User(name=user.name, email=user.email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Function to get a user by email
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

# Function to get all users
def get_users(db: Session, skip: int = 0, limit: int = 10):
    return db.query(User).offset(skip).limit(limit).all()

# Function to update a user
def update_user(db: Session, user_id: int, user: UserUpdate):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user:
        if user.name is not None:
            db_user.name = user.name
        if user.email is not None:
            db_user.email = user.email
        db.commit()
        db.refresh(db_user)
        return db_user
    return None

# Function to create an OSINT record
def create_osint_record(db: Session, record: OSINTRecordCreate):
    db_record = OSINTRecord(**record.dict())
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

# Function to get all OSINT records
def get_osint_records(db: Session, skip: int = 0, limit: int = 10):
    return db.query(OSINTRecord).offset(skip).limit(limit).all()
