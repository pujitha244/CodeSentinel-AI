# backend/config.py
import os

# Credentials are supplied through the environment and intentionally not
# committed with this sample project.
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
DATABASE_URL = "sqlite:///./app.db"
ADMIN_DEFAULT_PASSWORD = os.getenv("ADMIN_DEFAULT_PASSWORD", "")

# Insecure debug configuration
DEBUG_MODE = True
ALLOW_ALL_ORIGINS = ["*"]
