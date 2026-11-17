import os
from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CodeSentinel AI"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOADS_DIR: Path = DATA_DIR / "uploads"
    PROJECTS_DIR: Path = DATA_DIR / "projects"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    SAMPLE_PROJECTS_DIR: Path = BASE_DIR.parent / "sample-projects"
    
    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'codesentinel.db'}"
    
    # Security & Limits
    MAX_UPLOAD_SIZE_MB: int = 50
    MAX_FILE_COUNT: int = 5000
    MAX_FILE_SIZE_KB: int = 2048
    ALLOWED_EXTENSIONS: set = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".go",
        ".json", ".yaml", ".yml", ".toml", ".sh", ".dockerfile", "dockerfile",
        ".html", ".css", ".md", ".txt"
    }
    
    # AI Engine Settings
    AI_PROVIDER: str = "auto"  # 'rule_only', 'ollama', 'openai', or 'auto'
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    
    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000"
    ]

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()

# Ensure directories exist
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
settings.PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
