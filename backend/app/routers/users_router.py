# backend/app/routers/users_router.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app import crud
from backend.app.schemas.schemas import User, UserCreate, UserUpdate
from backend.app.database import SessionLocal
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/users/", response_model=User, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Create a new user. Returns the created user object."""
    logger.info(f"Attempting to create user with email: {user.email}")
    db_user = crud.get_user_by_email(db=db, email=user.email)
    if db_user:
        logger.warning(f"User creation failed: Email {user.email} already registered.")
        raise HTTPException(status_code=400, detail="Email already registered")
    created = crud.create_user(db=db, user=user)
    logger.info(f"User created with id: {created.id}")
    return created

@router.get("/users/", response_model=list[User])
def get_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve a list of users with pagination."""
    logger.info(f"Fetching users: skip={skip}, limit={limit}")
    return crud.get_users(db=db, skip=skip, limit=limit)

@router.put("/users/{user_id}", response_model=User)
def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    """Update an existing user by user_id."""
    logger.info(f"Updating user with id: {user_id}")
    db_user = crud.update_user(db=db, user_id=user_id, user=user)
    if not db_user:
        logger.warning(f"User update failed: User id {user_id} not found.")
        raise HTTPException(status_code=404, detail="User not found")
    logger.info(f"User updated: id={db_user.id}")
    return db_user
