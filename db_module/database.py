# db_module/database.py
import psycopg2
from psycopg2.extras import RealDictCursor
import os

# Параметры подключения к PostgreSQL
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'logmonitor',      # Название БД (создаю позже)
    'user': 'postgres',
    'password': 'l150506'        # пароль для superuser
}

def get_connection():
    """Создает и возвращает подключение к базе данных"""
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    """Создает таблицы, если их нет"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Таблица пользователей
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            twofa_secret TEXT
        )
    """)
    
    # Таблица агрегированных логов
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs_aggregated (
            id SERIAL PRIMARY KEY,
            time_bucket TIMESTAMP NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            details_json JSONB
        )
    """)
    
    # Таблица для быстрых алертов
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            occurred_at TIMESTAMP DEFAULT NOW(),
            source TEXT,
            message TEXT,
            raw_log TEXT
        )
    """)
    
    conn.commit()
    cur.close()
    conn.close()
    print("✅ База данных инициализирована")

def save_aggregated_data(time_bucket, event_type, source, count, details=None):
    """Сохраняет агрегированные данные в БД"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO logs_aggregated (time_bucket, event_type, source, count, details_json)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """, (time_bucket, event_type, source, count, details))
    
    conn.commit()
    cur.close()
    conn.close()

def save_alert(source, message, raw_log):
    """Сохраняет критическое событие в таблицу alerts"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO alerts (source, message, raw_log)
        VALUES (%s, %s, %s)
    """, (source, message, raw_log))
    
    conn.commit()
    cur.close()
    conn.close()

def get_alerts(limit=50):
    """Возвращает последние алерты"""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT * FROM alerts 
        ORDER BY occurred_at DESC 
        LIMIT %s
    """, (limit,))
    
    alerts = cur.fetchall()
    cur.close()
    conn.close()
    return alerts