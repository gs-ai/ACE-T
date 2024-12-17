from backend.app.models import Base
from backend.app.database import engine

# Recreate tables based on models
Base.metadata.create_all(bind=engine)
print("Database recreated successfully!")
