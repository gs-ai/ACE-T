# backend/app/main.py
import logging
from fastapi import FastAPI
from backend.app.routers import users_router
from backend.app.routers import osint_router

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ACE-T API", description="Advanced Cyber-Enabled Threat Intelligence Platform API")

@app.on_event("startup")
async def startup_event():
    logger.info("ACE-T API is starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("ACE-T API is shutting down...")

# Include user management router
app.include_router(users_router.router, prefix="/api", tags=["users"])
app.include_router(osint_router.router, prefix="/api", tags=["osint"])

@app.get("/", tags=["root"])
def read_root():
    """Root endpoint for health check and welcome message."""
    logger.info("Root endpoint accessed.")
    return {"message": "Welcome to ACE-T API"}

@app.get("/health", tags=["root"])
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}
