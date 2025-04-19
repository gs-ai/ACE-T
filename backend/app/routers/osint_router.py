from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app import crud
from backend.app.schemas.schemas import OSINTRecord, OSINTRecordCreate
from backend.app.database import SessionLocal

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/osint/", response_model=OSINTRecord, status_code=status.HTTP_201_CREATED)
def create_osint_record(record: OSINTRecordCreate, db: Session = Depends(get_db)):
    """Ingest a new OSINT record."""
    return crud.create_osint_record(db=db, record=record)

@router.get("/osint/", response_model=list[OSINTRecord])
def get_osint_records(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """List ingested OSINT records. Returns an empty list if none exist."""
    records = crud.get_osint_records(db=db, skip=skip, limit=limit)
    return records or []