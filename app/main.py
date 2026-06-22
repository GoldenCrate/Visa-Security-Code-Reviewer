from fastapi import FastAPI

from app.database import init_db
from app.api import health

init_db()

app = FastAPI(title="Visa Security Code Reviewer", version="1.0.0")
app.include_router(health.router)
