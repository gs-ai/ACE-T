from backend.app.models import Base
from backend.app.database import engine
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def recreate_database():
    try:
        logger.info("Starting database recreation process.")
        # Recreate tables based on models
        Base.metadata.create_all(bind=engine)
        logger.info("Database recreated successfully!")
    except Exception as e:
        logger.error(f"An error occurred while recreating the database: {e}")
        raise

if __name__ == "__main__":
    recreate_database()
