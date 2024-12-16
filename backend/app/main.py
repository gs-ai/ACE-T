from fastapi import FastAPI
from app.routers import users_router  

app = FastAPI()

# Include the users router with prefix /api and tags
app.include_router(users_router.router, prefix="/api", tags=["users"])

@app.get("/")
def read_root():
    return {"message": "Welcome to ACE-T API"}
