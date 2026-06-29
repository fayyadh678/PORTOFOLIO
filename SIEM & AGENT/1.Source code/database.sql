CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_host TEXT,
    event_type TEXT,
    severity TEXT,
    message TEXT,
    raw_log TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_id INTEGER,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    FOREIGN KEY(event_id) REFERENCES events(id)
);
