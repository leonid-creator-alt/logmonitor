# db_module/main.py
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import database as db
from datetime import datetime

app = FastAPI(title="LogMonitor DB Module")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- МОДЕЛИ ДАННЫХ ----------

class UserCreate(BaseModel):
    username: str
    password: str
    twofa_secret: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    twofa_enabled: bool
    created_at: datetime

class AlertData(BaseModel):
    source: str
    message: str
    level: str = "Info"
    log_name: str = ""
    event_id: str = ""
    is_error: bool = False
    is_critical: bool = False
    timestamp: Optional[str] = None

class TwoFASetup(BaseModel):
    username: str
    secret: str
    enabled: bool = True

class TwoFAVerify(BaseModel):
    username: str
    code: str

# ---------- ЭНДПОИНТЫ ПОЛЬЗОВАТЕЛЕЙ ----------

@app.on_event("startup")
async def startup():
    db.init_db()
    # Создаём тестового пользователя, если нет
    if not db.get_user_by_username("admin"):
        db.create_user("admin", "admin123")
        print("✅ Создан тестовый пользователь admin/admin123")
    print("🚀 DB Module on http://localhost:8081")

@app.post("/api/user/register")
async def register_user(user: UserCreate):
    """Регистрация нового пользователя"""
    success = db.create_user(user.username, user.password, user.twofa_secret)
    if not success:
        raise HTTPException(status_code=400, detail="Username already exists")
    return {"status": "created", "username": user.username}

@app.post("/api/user/verify-password")
async def verify_password(login: UserLogin):
    """Проверка пароля для авторизации"""
    valid = db.verify_user_password(login.username, login.password)
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Возвращаем информацию о 2FA
    twofa_enabled = db.is_2fa_enabled(login.username)
    return {
        "valid": True, 
        "twofa_enabled": twofa_enabled,
        "username": login.username
    }

@app.get("/api/user/{username}/2fa-status")
async def get_2fa_status(username: str):
    """Проверяет, включена ли 2FA"""
    enabled = db.is_2fa_enabled(username)
    return {"username": username, "twofa_enabled": enabled}

@app.post("/api/user/setup-2fa")
async def setup_2fa(data: TwoFASetup):
    """Сохраняет 2FA секрет для пользователя"""
    success = db.update_user_2fa(data.username, data.secret, data.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "updated"}

@app.get("/api/user/{username}/twofa-secret")
async def get_twofa_secret(username: str):
    """Возвращает 2FA секрет пользователя (для настройки)"""
    secret = db.get_user_2fa_secret(username)
    if secret is None:
        raise HTTPException(status_code=404, detail="User or 2FA secret not found")
    return {"username": username, "twofa_secret": secret}

# ---------- ЭНДПОИНТЫ СОБЫТИЙ ----------

@app.post("/api/alert")
async def save_alert(data: AlertData):
    """Сохраняет событие"""
    try:
        event_dict = data.dict()
        db.save_event(event_dict)
        return {"status": "saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/events")
async def get_events(limit: int = 100):
    """Возвращает последние события"""
    try:
        events = db.get_recent_events(limit)
        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)