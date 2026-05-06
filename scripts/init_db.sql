-- scripts/init_db.sql
CREATE DATABASE IF NOT EXISTS logmonitor;

\c logmonitor;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    twofa_secret TEXT
);

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
);

CREATE TABLE IF NOT EXISTS stats (
    id SERIAL PRIMARY KEY,
    time_bucket TIMESTAMP NOT NULL,
    log_name TEXT,
    total_events INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0
);