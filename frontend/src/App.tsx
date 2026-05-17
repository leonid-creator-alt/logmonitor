import React, { useState, useEffect, useRef } from 'react';
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, PieChart, Pie, ResponsiveContainer } from 'recharts';
import './App.css';

// Типы данных
interface LogEvent {
  log_name: string;
  timestamp: string;
  level: string;
  source: string;
  event_id: string;
  message: string;
  is_error: boolean;
  is_critical: boolean;
}

type Page = 'login' | 'register' | 'twofa' | 'dashboard';

function App() {
  // Состояния страниц
  const [page, setPage] = useState<Page>('login');
  const [error, setError] = useState('');

  // Данные пользователя
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [twoFACode, setTwoFACode] = useState('');
  const [token, setToken] = useState<string | null>(null);

  // Данные логов
  const [logs, setLogs] = useState<LogEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // Статистика для графиков
  const [errorCounts, setErrorCounts] = useState<{ time: string; count: number }[]>([]);
  const [levelDistribution, setLevelDistribution] = useState<{ name: string; value: number }[]>([]);

  // Состояния для модального окна 2FA
  const [show2FAModal, setShow2FAModal] = useState(false);
  const [qrCodeData, setQrCodeData] = useState('');
  const [twoFASecret, setTwoFASecret] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [verificationError, setVerificationError] = useState('');

  // --- Регистрация ---
  const handleRegister = async () => {
    setError('');
    try {
      const res = await fetch('http://localhost:8080/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (res.ok) {
        setPage('login');
        setPassword('');
      } else {
        setError(data.error || 'Ошибка регистрации');
      }
    } catch (err) {
      setError('Сервер недоступен');
    }
  };

  // --- Логин (первый шаг) ---
  const handleLogin = async () => {
    setError('');
    try {
      const res = await fetch('http://localhost:8080/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Неверные учётные данные');
        return;
      }
      if (data.require_2fa) {
        setPage('twofa');
      } else if (data.token) {
        setToken(data.token);
        localStorage.setItem('token', data.token);
        setPage('dashboard');
        connectWebSocket(data.token);
        fetchHistory(data.token);
      }
    } catch (err) {
      setError('Ошибка соединения');
    }
  };

  // --- Подтверждение 2FA ---
  const handleTwoFA = async () => {
    setError('');
    try {
      const res = await fetch('http://localhost:8080/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, twofa_code: twoFACode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Неверный код 2FA');
        return;
      }
      if (data.token) {
        setToken(data.token);
        localStorage.setItem('token', data.token);
        setPage('dashboard');
        connectWebSocket(data.token);
        fetchHistory(data.token);
      }
    } catch (err) {
      setError('Ошибка соединения');
    }
  };

  // --- Подключение WebSocket ---
  const connectWebSocket = (jwtToken: string) => {
    const ws = new WebSocket(`ws://localhost:8080/api/ws?token=${jwtToken}`);
    wsRef.current = ws;

    ws.onopen = () => console.log('WebSocket connected');
    ws.onmessage = (event) => {
      try {
        const newLog: LogEvent = JSON.parse(event.data);
        setLogs(prev => [newLog, ...prev].slice(0, 200));
        updateStats(newLog);
      } catch (e) {
        console.error('Parse error', e);
      }
    };
    ws.onerror = (err) => console.error('WebSocket error', err);
    ws.onclose = () => console.log('WebSocket closed');
  };

  const updateStats = (log: LogEvent) => {
    // линейный график ошибок по минутам
    const now = new Date();
    const minute = `${now.getHours()}:${now.getMinutes()}`;
    setErrorCounts(prev => {
      const existingIndex = prev.findIndex(p => p.time === minute);
      if (existingIndex >= 0) {
        const updated = [...prev];
        updated[existingIndex] = {
          ...updated[existingIndex],
          count: updated[existingIndex].count + (log.is_error ? 1 : 0)
        };
        return updated;
      } else {
        return [...prev.slice(-19), { time: minute, count: log.is_error ? 1 : 0 }];
      }
    });

    // распределение по уровням
    setLevelDistribution(prev => {
      const existingIndex = prev.findIndex(p => p.name === log.level);
      if (existingIndex >= 0) {
        const updated = [...prev];
        updated[existingIndex] = {
          ...updated[existingIndex],
          value: updated[existingIndex].value + 1
        };
        return updated;
      } else {
        return [...prev, { name: log.level, value: 1 }];
      }
    });
  };

  const fetchHistory = async (jwtToken: string) => {
    try {
      const res = await fetch('http://localhost:8080/api/events', {
        headers: { 'Authorization': `Bearer ${jwtToken}` },
      });
      const data = await res.json();
      if (data.events && data.events.length) {
        setLogs(data.events.slice(0, 200));
        
        const errorsByMinute = new Map<string, number>();
        const levelCounts = new Map<string, number>();
        
        data.events.forEach((ev: LogEvent) => {
          if (ev.timestamp) {
            const minute = new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            if (ev.is_error) {
              errorsByMinute.set(minute, (errorsByMinute.get(minute) || 0) + 1);
            }
          }
          levelCounts.set(ev.level, (levelCounts.get(ev.level) || 0) + 1);
        });
        
        setErrorCounts(Array.from(errorsByMinute.entries()).map(([time, count]) => ({ time, count })).slice(-20));
        setLevelDistribution(Array.from(levelCounts.entries()).map(([name, value]) => ({ name, value })));
      }
    } catch (err) {
      console.error('History fetch error', err);
    }
  };

  // Выход
  const handleLogout = () => {
    if (wsRef.current) wsRef.current.close();
    localStorage.removeItem('token');
    setToken(null);
    setPage('login');
    setLogs([]);
    setErrorCounts([]);
    setLevelDistribution([]);
  };

  const setup2FA = async () => {
    if (!token) return;
    try {
      const res = await fetch(`http://localhost:8080/api/setup-2fa?username=${username}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await res.json();
      if (data.qr_code && data.secret) {
        setQrCodeData(data.qr_code);
        setTwoFASecret(data.secret);
        setShow2FAModal(true);
      } else {
        alert('Ошибка генерации 2FA');
      }
    } catch (err) {
      console.error(err);
      alert('Ошибка соединения');
    }
  };

  const verify2FA = async () => {
    setVerificationError('');
    try {
      const res = await fetch('http://localhost:8080/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, twofa_code: verificationCode }),
      });
      const data = await res.json();
      if (data.token) {
        setShow2FAModal(false);
        alert('2FA успешно настроена! При следующем входе потребуется код.');
        localStorage.setItem('token', data.token);
        setToken(data.token);
        setVerificationCode('');
      } else {
        setVerificationError('Неверный код. Попробуйте ещё раз.');
      }
    } catch (err) {
      setVerificationError('Ошибка проверки кода');
    }
  };

  // Проверка сохранённого токена при загрузке приложения
  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    if (savedToken) {
      setToken(savedToken);
      setPage('dashboard');
      connectWebSocket(savedToken);
      fetchHistory(savedToken);
    }
  }, []);

  // --- Рендер страниц ---
  if (page === 'login') {
    return (
      <div className="container">
        <h1>📊 LogMonitor</h1>
        <input type="text" placeholder="Логин" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Пароль" value={password} onChange={e => setPassword(e.target.value)} onKeyPress={e => e.key === 'Enter' && handleLogin()} />
        <button onClick={handleLogin}>Войти</button>
        <button className="secondary" onClick={() => setPage('register')}>Регистрация</button>
        {error && <p className="error">{error}</p>}
        <p className="hint">Тестовый пользователь: admin / admin123</p>
      </div>
    );
  }

  if (page === 'register') {
    return (
      <div className="container">
        <h1>📝 Регистрация</h1>
        <input type="text" placeholder="Логин" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Пароль" value={password} onChange={e => setPassword(e.target.value)} onKeyPress={e => e.key === 'Enter' && handleRegister()} />
        <button onClick={handleRegister}>Зарегистрироваться</button>
        <button className="secondary" onClick={() => setPage('login')}>Назад</button>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  if (page === 'twofa') {
    return (
      <div className="container">
        <h1>🔐 Двухфакторная аутентификация</h1>
        <p>Введите код из Google Authenticator</p>
        <input type="text" placeholder="6-значный код" value={twoFACode} onChange={e => setTwoFACode(e.target.value)} onKeyPress={e => e.key === 'Enter' && handleTwoFA()} />
        <button onClick={handleTwoFA}>Подтвердить</button>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  // Дашборд
  const errorCount = logs.filter(l => l.is_error).length;
  const criticalCount = logs.filter(l => l.is_critical).length;

  return (
    <div className="dashboard">
      <div className="header">
        <h1>📊 LogMonitor – Дашборд логов</h1>
        <button onClick={handleLogout}>Выйти</button>
        <button onClick={setup2FA} className="setup-2fa">🔐 Настроить 2FA</button>
      </div>

      {/* Карточки статистики */}
      <div className="stats">
        <div className="stat-card">📝 Всего событий: {logs.length}</div>
        <div className="stat-card error">❌ Ошибок: {errorCount}</div>
        <div className="stat-card critical">⚠️ Критических: {criticalCount}</div>
      </div>

      {/* Графики */}
      <div className="charts">
        <div className="chart-box">
          <h3>Ошибки по минутам</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={errorCounts}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#8884d8" />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-box">
          <h3>Распределение по уровням</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={levelDistribution} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} fill="#82ca9d" label />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Таблица последних логов */}
      <div className="logs-table">
        <h3>Последние логи (в реальном времени)</h3>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Уровень</th>
                <th>Источник</th>
                <th>Event ID</th>
                <th>Сообщение</th>
              </tr>
            </thead>
            <tbody>
              {logs.slice(0, 50).map((log, idx) => (
                <tr key={idx} className={log.is_critical ? 'critical-row' : log.is_error ? 'error-row' : ''}>
                  <td className="level">{log.level}</td>
                  <td>{log.source}</td>
                  <td>{log.event_id}</td>
                  <td className="message">{log.message?.slice(0, 100)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Модальное окно для настройки 2FA */}
      {show2FAModal && (
        <div className="modal-overlay" onClick={() => setShow2FAModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>🔐 Настройка двухфакторной аутентификации</h3>
            <p>Отсканируйте QR-код в приложении Google Authenticator:</p>
            <img src={qrCodeData} alt="QR Code" style={{ width: '200px', height: '200px', margin: '10px auto', display: 'block' }} />
            <p>Или введите секрет вручную: <code>{twoFASecret}</code></p>
            <p>После сканирования введите полученный 6-значный код:</p>
            <input
              type="text"
              placeholder="6-значный код"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              maxLength={6}
            />
            <button onClick={verify2FA}>Подтвердить</button>
            {verificationError && <p className="error">{verificationError}</p>}
            <button className="secondary" onClick={() => setShow2FAModal(false)}>Закрыть</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;