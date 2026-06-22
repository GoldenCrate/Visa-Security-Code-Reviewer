from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import init_db
from app.api import health


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup (idempotent) rather than at import time.
    init_db()
    yield


app = FastAPI(
    title="Visa Security Code Reviewer",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(health.router)
