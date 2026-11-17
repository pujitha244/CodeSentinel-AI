import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import engine, Base
from backend.app.api.routes_health import router as health_router
from backend.app.api.routes_projects import router as projects_router
from backend.app.api.routes_audits import router as audits_router
from backend.app.api.routes_findings import router as findings_router
from backend.app.api.routes_remediation import router as remediation_router
from backend.app.api.routes_assistant import router as assistant_router
from backend.app.api.routes_reports import router as reports_router
from backend.app.api.routes_files import router as files_router

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("CodeSentinel")

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "CodeSentinel AI: Autonomous Security Intelligence, Cross-File Vulnerability Detection "
        "& Software Engineering Audit Platform."
    ),
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for development & local frontend access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(projects_router, prefix=settings.API_PREFIX)
app.include_router(audits_router, prefix=settings.API_PREFIX)
app.include_router(findings_router, prefix=settings.API_PREFIX)
app.include_router(remediation_router, prefix=settings.API_PREFIX)
app.include_router(assistant_router, prefix=settings.API_PREFIX)
app.include_router(reports_router, prefix=settings.API_PREFIX)
app.include_router(files_router, prefix=settings.API_PREFIX)

@app.on_event("startup")
def on_startup():
    logger.info("🛡️ CodeSentinel AI Backend started successfully on FastAPI.")
    logger.info(f"AI Provider mode: {settings.AI_PROVIDER}")
