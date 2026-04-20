# db_module/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any
import database as db

# Создаем FastAPI приложение
app = FastAPI(title="LogMonitor DB Module")

# Разрешаем CORS (чтобы Go мог обращаться к этому сервису)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # В продакшене ограничить!
    allow_methods=["*"],
    allow_headers=["*"],
)

# Модели данных для валидации
class LogData(BaseModel):
    time_bucket: datetime
    event_type: str      # "Error", "Warning", "Info"
    source: str          # "System", "Application"
    count: int
    details: Optional[Dict[str, Any]] = None

class AlertData(BaseModel):
    source: str
    message: str
    raw_log: str

# Эндпоинты API

@app.on_event("startup")
async def startup_event():
    """При запуске сервера создаем таблицы"""
    db.init_db()
    print("🚀 DB Module started on http://localhost:8081")

@app.get("/health")
async def health_check():
    """Проверка работоспособности"""
    return {"status": "ok", "service": "db-module"}

@app.post("/api/stats")
async def save_stats(data: LogData):
    """Сохраняет агрегированную статистику"""
    try:
        db.save_aggregated_data(
            data.time_bucket,
            data.event_type,
            data.source,
            data.count,
            data.details
        )
        return {"status": "saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alert")
async def save_alert(data: AlertData):
    """Сохраняет алерт"""
    try:
        db.save_alert(data.source, data.message, data.raw_log)
        return {"status": "alert_saved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Возвращает последние алерты"""
    try:
        alerts = db.get_alerts(limit)
        return {"alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)