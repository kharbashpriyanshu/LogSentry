import logging
import sys
from logging.handlers import RotatingFileHandler
import os
from app.config.settings import settings

def setup_logging() -> None:
    """Configure enterprise logging system."""
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(settings.LOG_FILE_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        
    logger = logging.getLogger()
    logger.setLevel(settings.LOG_LEVEL)
    
    # Formatter for structured logs
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # File Handler (Rotating)
    # For rotation based on bytes (e.g. 500 MB roughly 500 * 1024 * 1024 bytes)
    file_handler = RotatingFileHandler(
        settings.LOG_FILE_PATH,
        maxBytes=500 * 1024 * 1024,
        backupCount=10
    )
    file_handler.setFormatter(formatter)
    
    # Avoid duplicating logs
    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    logging.info("Logging configured successfully.")
