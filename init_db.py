from app.database.base import Base
from app.database.session import engine
import app.models

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Tables created.")
