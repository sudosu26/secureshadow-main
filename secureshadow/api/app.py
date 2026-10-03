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
from fastapi.responses import FileResponse

from ..db.database import init_db, SessionLocal
from .auth import seed_admin_user
from .routes import router as api_router

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
    version="0.4.0",
    lifespan=lifespan,
)

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
            return FileResponse(status_code=404)
        target = STATIC_DIR / full_path
        if target.exists() and target.is_file():
            return FileResponse(str(target))
        return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health", tags=["System"])
def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "secureshadow", "version": "0.4.0"}
