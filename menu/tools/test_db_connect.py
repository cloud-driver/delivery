"""Simple DB connection tester.

Reads the DB URL from the environment variable DATABASE_URL, then
from data/db_link, then falls back to a sensible default. Attempts to
connect using SQLAlchemy and runs `SELECT 1`. If successful, lists
available tables (best-effort).
"""
import os
import sys
import traceback
from pathlib import Path

from sqlalchemy import create_engine, text, inspect


def load_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    p = Path(__file__).resolve().parents[1] / "data" / "db_link"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    return "mysql+pymysql://root:@127.0.0.1:3306/e-system-delivery?charset=utf8mb4"


def main():
    url = load_db_url()
    print("Using DB URL:", url)
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            print("Connected to database server successfully.")
            # test simple query
            result = conn.execute(text("SELECT 1"))
            print("SELECT 1 ->", list(result))
            try:
                inspector = inspect(engine)
                tables = inspector.get_table_names()
                print(f"Found {len(tables)} tables (showing up to 20):")
                for t in tables[:20]:
                    print(" -", t)
            except Exception:
                print("Could not inspect tables (permission or dialect issue).")
    except Exception as exc:
        print("Failed to connect to database:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
