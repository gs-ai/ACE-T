# initialize_db.py
from backend.app.database import Base, engine
from backend.app.models.models import User
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    # Create the database tables
    Base.metadata.create_all(bind=engine)
    logging.info("Database tables created successfully.")
except Exception as e:
    logging.error(f"Error creating database tables: {e}")
