"""
SECURESHADOW - FastAPI Application Instance
Provides REST endpoints and serves the unified web dashboard.
"""

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from sqlalchemy import text

from ..db.database import init_db, SessionLocal
from .auth import seed_admin_user
from .routes import router as api_router, limiter

STATIC_DIR = Path(__file__).parent.parent / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secureshadow")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables, default admin account, and background scheduler."""
    init_db()
    db = SessionLocal()
    try:
        seed_admin_user(db)
    finally:
        db.close()

    scheduler_enabled = os.getenv("ENABLE_SCHEDULER", "true").lower() in ("true", "1", "yes")
    if scheduler_enabled:
        from .scheduler import start_scheduler, shutdown_scheduler
        try:
            start_scheduler()
        except Exception as e:
            logger.warning("Failed to start background scheduler: %s", e)

    yield

    if scheduler_enabled:
        from .scheduler import shutdown_scheduler
        try:
            shutdown_scheduler()
        except Exception as e:
            logger.warning("Failed to stop background scheduler: %s", e)


app = FastAPI(
    title="SECURESHADOW API",
    description="Silent Security Control Degradation & Architectural Drift Detection System",
    version="0.5.0",
    lifespan=lifespan,
)

# Register slowapi rate limiter state and exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enable CORS (Configurable via environment variables for production safety)
cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)


# Mount static assets and serve root UI / SPA fallback
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str):
        """Serve SPA index.html for root and client-side routes, or static files."""
        if full_path.startswith("api/") or full_path == "api":
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        target = STATIC_DIR / full_path
        if target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health", tags=["System"])
def health_check():
    """
    Comprehensive operational healthcheck verifying API and active database connectivity.
    """
    db_ok = False
    db_error = None
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            db_ok = True
        finally:
            db.close()
    except Exception as e:
        db_error = str(e)
        logger.error("Healthcheck: Database connectivity failed: %s", e)

    if not db_ok:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "secureshadow",
                "version": "0.5.0",
                "database": {"connected": False, "error": db_error},
            },
        )

    return {
        "status": "healthy",
        "service": "secureshadow",
        "version": "0.5.0",
        "database": {"connected": True},
    }
