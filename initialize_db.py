# initialize_db.py
from backend.app.database import Base, engine
from backend.app.models.models import User

# Create the database tables
Base.metadata.create_all(bind=engine)
