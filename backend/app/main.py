# backend/app/main.py
import logging
from fastapi import FastAPI
from backend.app.routers import users_router

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

@app.on_event("startup")
async def startup_event():
    logger.info("ACE-T API is starting up...")

# Include user management router
app.include_router(users_router.router, prefix="/api", tags=["users"])

@app.get("/")
def read_root():
    logger.info("Root endpoint accessed.")
    return {"message": "Welcome to ACE-T API"}
