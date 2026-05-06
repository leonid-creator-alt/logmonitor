# db_module/database.py
import psycopg2
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext
from datetime import datetime
from typing import Optional, Dict, Any, List

# Настройка bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'logmonitor',
    'user': 'postgres',
    'password': 'l150506'  # твой пароль
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    """Создаёт все таблицы, если их нет"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Таблица пользователей (расширенная)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            twofa_secret TEXT,
            twofa_enabled BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    
    # Таблица событий (логи)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            log_name TEXT,
            level TEXT,
            source TEXT,
            event_id TEXT,
            message TEXT,
            is_error BOOLEAN,
            is_critical BOOLEAN,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    
    # Таблица агрегированной статистики
    cur.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id SERIAL PRIMARY KEY,
            time_bucket TIMESTAMP NOT NULL,
            log_name TEXT,
            total_events INTEGER DEFAULT 0,
            errors_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0
        )
    """)
    
    conn.commit()
    cur.close()
    conn.close()
    print("✅ База данных инициализирована")

# ---------- РАБОТА С ПОЛЬЗОВАТЕЛЯМИ ----------

def hash_password(password: str) -> str:
    """Хэширует пароль bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль"""
    return pwd_context.verify(plain_password, hashed_password)

def create_user(username: str, password: str, twofa_secret: str = None) -> bool:
    """Создаёт нового пользователя"""
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cur.execute("""
            INSERT INTO users (username, password_hash, twofa_secret, twofa_enabled)
            VALUES (%s, %s, %s, %s)
        """, (username, password_hash, twofa_secret, twofa_secret is not None))
        conn.commit()
        return True
    except psycopg2.IntegrityError:
        conn.rollback()
        return False
    finally:
        cur.close()
        conn.close()

def get_user_by_username(username: str) -> Optional[Dict]:
    """Получает пользователя по имени"""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    
    cur.close()
    conn.close()
    return user

def update_user_2fa(username: str, secret: str, enabled: bool = True) -> bool:
    """Обновляет 2FA секрет для пользователя"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        UPDATE users 
        SET twofa_secret = %s, twofa_enabled = %s 
        WHERE username = %s
    """, (secret, enabled, username))
    
    conn.commit()
    affected = cur.rowcount
    cur.close()
    conn.close()
    return affected > 0

def verify_user_password(username: str, password: str) -> bool:
    """Проверяет пароль пользователя"""
    user = get_user_by_username(username)
    if not user:
        return False
    return verify_password(password, user['password_hash'])

# ---------- РАБОТА С СОБЫТИЯМИ ----------

def save_event(event_data: dict):
    """Сохраняет событие в БД"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO events (timestamp, log_name, level, source, event_id, message, is_error, is_critical)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        event_data.get('timestamp'),
        event_data.get('log_name'),
        event_data.get('level'),
        event_data.get('source'),
        event_data.get('event_id'),
        event_data.get('message')[:1000] if event_data.get('message') else None,
        event_data.get('is_error', False),
        event_data.get('is_critical', False)
    ))
    
    conn.commit()
    cur.close()
    conn.close()

def get_recent_events(limit: int = 100) -> List[Dict]:
    """Возвращает последние события"""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT * FROM events 
        ORDER BY created_at DESC 
        LIMIT %s
    """, (limit,))
    
    events = cur.fetchall()
    cur.close()
    conn.close()
    return events

def get_user_2fa_secret(username: str) -> Optional[str]:
    """Возвращает 2FA секрет пользователя"""
    user = get_user_by_username(username)
    if user:
        return user.get('twofa_secret')
    return None

def is_2fa_enabled(username: str) -> bool:
    """Проверяет, включена ли 2FA для пользователя"""
    user = get_user_by_username(username)
    if user:
        return user.get('twofa_enabled', False)
    return False