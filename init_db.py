from app.database.base import Base
from app.database.session import engine

print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Tables created.")
