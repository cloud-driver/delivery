from sqlalchemy import create_engine, MetaData, Table, select
from sqlalchemy.orm import sessionmaker
import os
from pathlib import Path
import json

def _load_db_url_from_file() -> str:
    from pathlib import Path
    try:
        repo_root = Path(__file__).resolve().parents[3]
        db_file = repo_root / 'data' / 'db_link'
        if db_file.exists():
            return db_file.read_text(encoding='utf-8').strip()
    except Exception:
        pass
    # sensible default (local MySQL)
    return "mysql+pymysql://root:@127.0.0.1:3306/e-system-delivery?charset=utf8mb4"


SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or _load_db_url_from_file()
engine = create_engine(SQLALCHEMY_DATABASE_URI, echo=False)
Session = sessionmaker(bind=engine)
metadata = MetaData()

restaurant_table = None
try:
    restaurant_table = Table('restaurants', metadata, autoload_with=engine)
except Exception:
    restaurant_table = None

def get_restaurant_list():
    """取得所有店家清單（若 DB 不可用回傳簡單樣本）"""
    if restaurant_table is not None:
        with engine.connect() as conn:
            stmt = select(restaurant_table)
            result = conn.execute(stmt).mappings().all()
            return [dict(row) for row in result]

    # fallback sample
    return [
        {"restaurant_id": "R002", "name": "示範餐廳 R002"},
        {"restaurant_id": "R001", "name": "示範餐廳 R001"}
    ]

def get_restaurant_by_id(restaurant_id):
    """取得指定店家資訊（fallback sample）"""
    if restaurant_table is not None:
        with engine.connect() as conn:
            stmt = select(restaurant_table).where(restaurant_table.c.id == restaurant_id)
            result = conn.execute(stmt).mappings().fetchone()
            if result:
                return dict(result)
            return None

    for r in get_restaurant_list():
        if str(r.get('restaurant_id')) == str(restaurant_id) or str(r.get('id')) == str(restaurant_id):
            return r
    return None