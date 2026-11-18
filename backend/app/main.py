import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.auth import configured_access_token, request_has_valid_access
from backend.app.core.config import settings
from backend.app.core.database import engine, Base
from backend.app.api.routes_health import router as health_router
from backend.app.api.routes_auth import router as auth_router
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
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PUBLIC_API_PATHS = {
    f"{settings.API_PREFIX}/health",
    f"{settings.API_PREFIX}/auth/session",
}


@app.middleware("http")
async def require_api_access(request: Request, call_next):
    path = request.url.path
    if (
        settings.API_AUTH_ENABLED
        and
        path.startswith(f"{settings.API_PREFIX}/")
        and path not in PUBLIC_API_PATHS
        and request.method != "OPTIONS"
    ):
        if configured_access_token() is None:
            return JSONResponse(
                status_code=503,
                content={"detail": "Protected API is unavailable until API_ACCESS_TOKEN is configured."},
            )
        if not request_has_valid_access(request):
            return JSONResponse(status_code=401, content={"detail": "Authentication required."})
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and origin not in settings.CORS_ORIGINS:
                return JSONResponse(status_code=403, content={"detail": "Request origin is not allowed."})

    return await call_next(request)

# Global Exception Handlers to guarantee JSON responses
@app.exception_handler(ResponseValidationError)
async def response_validation_exception_handler(request: Request, exc: ResponseValidationError):
    logger.error("Response validation error at %s (%d issues)", request.url.path, len(exc.errors()))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal response validation error."}
    )

@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.info("Request validation failed at %s (%d issues)", request.url.path, len(exc.errors()))
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": error.get("loc"), "msg": error.get("msg"), "type": error.get("type")}
                for error in exc.errors()
            ]
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(
        "Unhandled exception at %s (%s)",
        request.url.path,
        type(exc).__name__
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."}
    )

# Mount Routers
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(auth_router, prefix=settings.API_PREFIX)
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
    if settings.API_AUTH_ENABLED and configured_access_token() is None:
        logger.warning(
            "Protected API is disabled until API_ACCESS_TOKEN is configured with at least %d characters.",
            32,
        )
