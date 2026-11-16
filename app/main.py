# app/main.py
import logging
from logging.handlers import RotatingFileHandler
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers import firewall, views

# ------------------------
# Logging Setup
# ------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=3)
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[handler, logging.StreamHandler()])
logger = logging.getLogger("main")

logger.info("Initializing UniFi Firewall Control App")

# ------------------------
# FastAPI App Setup
# ------------------------
app = FastAPI(title="UniFi Firewall Toggle")

# Static Files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Routers
app.include_router(views.router)
app.include_router(firewall.router)
