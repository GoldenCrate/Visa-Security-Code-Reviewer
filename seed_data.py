"""CLI to seed the database with synthetic demo scans for a richer dashboard.

Demo/local data only — real scans come from the Review page's live LLM flow.
Re-running wipes and reseeds (idempotent, reproducible).

Usage:  python seed_data.py
"""

from app.database import SessionLocal, init_db
from app.demo_seed import NUM_SCANS, seed


def main():
    init_db()
    db = SessionLocal()
    try:
        count = seed(db)
        print(f"Seeded {NUM_SCANS} scans with {count} findings.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
