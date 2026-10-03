"""
SECURESHADOW - Background Re-Detection Scheduler
Uses APScheduler to periodically re-evaluate infrastructure drift and recalculate decay.
"""

import os
import logging
from pathlib import Path
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ..db.database import SessionLocal
from .routes import execute_detection_pipeline, engine_state, record_audit_log
from ..loaders.terraform import TerraformLoader

logger = logging.getLogger("secureshadow.scheduler")

scheduler: AsyncIOScheduler = AsyncIOScheduler()


async def scheduled_detection_job():
    """
    Scheduled re-detection task:
    1. Re-loads current assets from configured Terraform plan path if provided.
    2. Re-runs drift detection against the stored baseline.
    3. Persists detection results, updates decay, and records audit log.
    """
    db = SessionLocal()
    try:
        if not engine_state["baseline_graph"]:
            logger.info("Scheduler: Baseline not yet established. Skipping scan.")
            return

        tf_path_env = os.getenv("SCHEDULED_TERRAFORM_PLAN_PATH")
        if tf_path_env and Path(tf_path_env).exists():
            loader = TerraformLoader()
            graph, _, _ = loader.build_graph_from_json(tf_path_env)
            engine_state["current_graph"] = graph
            logger.info("Scheduler: Ingested current state from %s", tf_path_env)

        if not engine_state["current_graph"]:
            logger.info("Scheduler: Current graph not established. Skipping scan.")
            return

        res = execute_detection_pipeline(db, username="scheduler")
        record_audit_log(
            db,
            username="scheduler",
            action="SCHEDULED_SCAN",
            entity_type="SYSTEM",
            details={
                "total_changes": res.total_changes,
                "critical": res.critical_count,
            },
        )
        logger.info(
            "Scheduler: Completed scan. Changes: %d, Critical: %d",
            res.total_changes,
            res.critical_count,
        )
    except Exception as e:
        logger.error("Scheduler error during scan: %s", str(e), exc_info=True)
    finally:
        db.close()


def start_scheduler():
    """Start background scheduler with configured interval."""
    interval_minutes = int(os.getenv("SCHEDULED_SCAN_INTERVAL_MINUTES", "15"))
    scheduler.add_job(
        scheduled_detection_job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="periodic_drift_scan",
        name="Periodic Infrastructure Drift & Decay Scan",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Background scheduler started (interval: %d minutes)", interval_minutes)


def shutdown_scheduler():
    """Gracefully shutdown scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Background scheduler stopped.")
