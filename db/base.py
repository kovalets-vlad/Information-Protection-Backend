import os
from sqlmodel import create_engine

# Зчитуємо URL з .env (який ми прописали в docker-compose)
# Якщо змінної немає, як фолбек можна залишити старий sqlite (для локальних тестів без докера)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database.db")

# Для PostgreSQL "connect_args" з check_same_thread НЕ ПОТРІБНІ (це фішка тільки для SQLite)
connect_args = {} 

if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)