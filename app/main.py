from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import settings
from app.database import SessionLocal, init_db
from app.api import health, scans, metrics


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (idempotent) rather than at import time.
    init_db()
    # On the public demo deploy, populate the dashboard if the DB is empty.
    if settings.seed_demo:
        from app.demo_seed import maybe_seed_if_empty

        db = SessionLocal()
        try:
            maybe_seed_if_empty(db)
        finally:
            db.close()
    yield


app = FastAPI(
    title="Visa Security Code Reviewer",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(health.router)
app.include_router(scans.router)
app.include_router(metrics.router)
