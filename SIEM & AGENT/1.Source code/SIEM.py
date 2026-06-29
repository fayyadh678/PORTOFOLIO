from flask import Flask, request, jsonify, Response, render_template_string
import sqlite3
import os
import csv
import io
import json
from datetime import datetime, timedelta

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(BASE_DIR, "siem.db")
SQL_PATH = os.path.join(BASE_DIR, "database.sql")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with open(SQL_PATH, "r") as f:
        sql = f.read()
    conn = get_db()
    conn.executescript(sql)
    conn.commit()
    conn.close()


def insert_alert(event_id, alert_type, severity, description):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO alerts (timestamp, event_id, alert_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
        """,
        (now(), event_id, alert_type, severity, description)
    )
    conn.commit()
    conn.close()


def evaluate_rules(event_id, event):
    event_type = event.get("event_type", "")
    severity = event.get("severity", "low")
    source_host = event.get("source_host", "unknown")
    message = event.get("message", "")
    raw_log = event.get("raw_log", "")

    text = f"{event_type} {message} {raw_log}".lower()

    # Rule 1: Failed SSH
    if event_type == "failed_ssh" or "failed password" in text:
        insert_alert(
            event_id,
            "FAILED_SSH_LOGIN",
            "high",
            f"Failed SSH login detected from {source_host}"
        )

    # Rule 2: Successful SSH
    elif event_type == "successful_ssh" or "accepted password" in text:
        insert_alert(
            event_id,
            "SUCCESSFUL_SSH_LOGIN",
            "low",
            f"Successful SSH login detected on {source_host}"
        )

    # Rule 3: Failed sudo
    elif event_type == "failed_sudo" or "incorrect password" in text:
        insert_alert(
            event_id,
            "FAILED_SUDO_ATTEMPT",
            "high",
            f"Failed sudo attempt detected on {source_host}"
        )

    # Rule 4: User account changes
    elif event_type in ["user_created", "user_deleted"]:
        insert_alert(
            event_id,
            "USER_ACCOUNT_CHANGE",
            "high",
            f"User account change detected on {source_host}: {message}"
        )

    # Rule 5: Package installation
    elif event_type == "package_install":
        insert_alert(
            event_id,
            "PACKAGE_INSTALLATION",
            "medium",
            f"Package installation detected on {source_host}"
        )

    # Rule 6: Service status change
    elif event_type in ["service_started", "service_stopped"]:
        insert_alert(
            event_id,
            "SERVICE_STATUS_CHANGE",
            "medium",
            f"Service status change detected on {source_host}: {message}"
        )

    # Rule 7: File operation
    elif event_type in ["file_created", "file_modified", "file_deleted"]:
        sev = "medium" if event_type == "file_deleted" else "low"
        insert_alert(
            event_id,
            "FILE_OPERATION",
            sev,
            f"File operation detected on {source_host}: {message}"
        )

    # Rule 8: Custom application log
    elif event_type == "custom_log":
        insert_alert(
            event_id,
            "CUSTOM_SECURITY_LOG",
            "medium",
            f"Custom security log detected on {source_host}: {message}"
        )

    # Rule 9: High severity generic event
    elif severity == "high":
        insert_alert(
            event_id,
            "HIGH_SEVERITY_EVENT",
            "high",
            f"High severity event detected on {source_host}: {message}"
        )

    # Rule 10: Brute force SSH, 3 failed SSH in 10 minutes
    if event_type == "failed_ssh":
        conn = get_db()
        ten_minutes_ago = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM events
            WHERE source_host = ?
            AND event_type = 'failed_ssh'
            AND timestamp >= ?
            """,
            (source_host, ten_minutes_ago)
        ).fetchone()["total"]
        conn.close()

        if count >= 3:
            insert_alert(
                event_id,
                "POSSIBLE_SSH_BRUTE_FORCE",
                "critical",
                f"Possible SSH brute force from/on {source_host}. Failed attempts in 10 minutes: {count}"
            )


@app.route("/")
def index():
    return dashboard()


@app.route("/api/events", methods=["POST"])
def receive_event():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    timestamp = data.get("timestamp") or now()
    source_host = data.get("source_host", "unknown")
    event_type = data.get("event_type", "unknown")
    severity = data.get("severity", "low")
    message = data.get("message", "")
    raw_log = data.get("raw_log", "")

    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO events (timestamp, source_host, event_type, severity, message, raw_log)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, source_host, event_type, severity, message, raw_log)
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()

    evaluate_rules(event_id, {
        "timestamp": timestamp,
        "source_host": source_host,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "raw_log": raw_log
    })

    return jsonify({
        "status": "success",
        "message": "Event received",
        "event_id": event_id
    }), 201


BASE_HTML = """
<!doctype html>
<html>
<head>
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            background: #f4f6f8;
            color: #222;
        }
        .navbar {
            background: #111827;
            color: white;
            padding: 15px 25px;
        }
        .navbar a {
            color: white;
            margin-right: 18px;
            text-decoration: none;
            font-weight: bold;
        }
        .container {
            padding: 25px;
        }
        .cards {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            min-width: 190px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .card h2 {
            margin: 0;
            font-size: 34px;
        }
        .card p {
            margin: 5px 0 0 0;
            color: #555;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-top: 20px;
            font-size: 14px;
        }
        th, td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }
        th {
            background: #e5e7eb;
            text-align: left;
        }
        .badge {
            padding: 4px 8px;
            border-radius: 8px;
            background: #e5e7eb;
            font-weight: bold;
        }
        .low { background: #dcfce7; }
        .medium { background: #fef9c3; }
        .high { background: #fee2e2; }
        .critical { background: #fecaca; color: #7f1d1d; }
        .filter-box {
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
        }
        input, select, button {
            padding: 8px;
            margin-right: 10px;
        }
        button {
            cursor: pointer;
        }
        pre {
            white-space: pre-wrap;
            word-break: break-word;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <a href="/dashboard">Dashboard</a>
        <a href="/events">Events</a>
        <a href="/alerts">Alerts</a>
        <a href="/export/events.csv">Export Events CSV</a>
        <a href="/export/alerts.csv">Export Alerts CSV</a>
        <a href="/report/summary.txt">Summary Report</a>
    </div>
    <div class="container">
        {{ content|safe }}
    </div>
</body>
</html>
"""


def page(title, content):
    return render_template_string(BASE_HTML, title=title, content=content)


@app.route("/dashboard")
def dashboard():
    conn = get_db()

    total_events = conn.execute("SELECT COUNT(*) AS total FROM events").fetchone()["total"]
    total_alerts = conn.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()["total"]
    critical_alerts = conn.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity='critical'").fetchone()["total"]
    high_alerts = conn.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity='high'").fetchone()["total"]

    recent_events = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 10"
    ).fetchall()

    recent_alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 10"
    ).fetchall()

    conn.close()

    event_rows = ""
    for e in recent_events:
        event_rows += f"""
        <tr>
            <td>{e['id']}</td>
            <td>{e['timestamp']}</td>
            <td>{e['source_host']}</td>
            <td>{e['event_type']}</td>
            <td><span class="badge {e['severity']}">{e['severity']}</span></td>
            <td>{e['message']}</td>
        </tr>
        """

    alert_rows = ""
    for a in recent_alerts:
        alert_rows += f"""
        <tr>
            <td>{a['id']}</td>
            <td>{a['timestamp']}</td>
            <td>{a['alert_type']}</td>
            <td><span class="badge {a['severity']}">{a['severity']}</span></td>
            <td>{a['description']}</td>
        </tr>
        """

    content = f"""
    <h1>SIEM Dashboard</h1>

    <div class="cards">
        <div class="card">
            <h2>{total_events}</h2>
            <p>Total Events</p>
        </div>
        <div class="card">
            <h2>{total_alerts}</h2>
            <p>Total Alerts</p>
        </div>
        <div class="card">
            <h2>{critical_alerts}</h2>
            <p>Critical Alerts</p>
        </div>
        <div class="card">
            <h2>{high_alerts}</h2>
            <p>High Alerts</p>
        </div>
    </div>

    <h2>Recent Events</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Message</th>
        </tr>
        {event_rows}
    </table>

    <h2>Recent Alerts</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Alert Type</th>
            <th>Severity</th>
            <th>Description</th>
        </tr>
        {alert_rows}
    </table>
    """

    return page("SIEM Dashboard", content)


@app.route("/events")
def events():
    event_type = request.args.get("type", "")
    severity = request.args.get("severity", "")
    source = request.args.get("source", "")

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if event_type:
        query += " AND event_type LIKE ?"
        params.append(f"%{event_type}%")

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if source:
        query += " AND source_host LIKE ?"
        params.append(f"%{source}%")

    query += " ORDER BY id DESC LIMIT 200"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    table_rows = ""
    for e in rows:
        table_rows += f"""
        <tr>
            <td>{e['id']}</td>
            <td>{e['timestamp']}</td>
            <td>{e['source_host']}</td>
            <td>{e['event_type']}</td>
            <td><span class="badge {e['severity']}">{e['severity']}</span></td>
            <td>{e['message']}</td>
            <td><pre>{e['raw_log']}</pre></td>
        </tr>
        """

    content = f"""
    <h1>Events</h1>

    <div class="filter-box">
        <form method="get" action="/events">
            <input name="type" placeholder="event type, contoh: failed_ssh" value="{event_type}">
            <select name="severity">
                <option value="">all severity</option>
                <option value="low" {"selected" if severity == "low" else ""}>low</option>
                <option value="medium" {"selected" if severity == "medium" else ""}>medium</option>
                <option value="high" {"selected" if severity == "high" else ""}>high</option>
                <option value="critical" {"selected" if severity == "critical" else ""}>critical</option>
            </select>
            <input name="source" placeholder="source host" value="{source}">
            <button type="submit">Filter</button>
        </form>
    </div>

    <table>
        <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Source</th>
            <th>Event Type</th>
            <th>Severity</th>
            <th>Message</th>
            <th>Raw Log</th>
        </tr>
        {table_rows}
    </table>
    """

    return page("Events", content)


@app.route("/alerts")
def alerts():
    severity = request.args.get("severity", "")
    alert_type = request.args.get("type", "")

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if alert_type:
        query += " AND alert_type LIKE ?"
        params.append(f"%{alert_type}%")

    query += " ORDER BY id DESC LIMIT 200"

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()

    table_rows = ""
    for a in rows:
        table_rows += f"""
        <tr>
            <td>{a['id']}</td>
            <td>{a['timestamp']}</td>
            <td>{a['event_id']}</td>
            <td>{a['alert_type']}</td>
            <td><span class="badge {a['severity']}">{a['severity']}</span></td>
            <td>{a['description']}</td>
        </tr>
        """

    content = f"""
    <h1>Alerts</h1>

    <div class="filter-box">
        <form method="get" action="/alerts">
            <input name="type" placeholder="alert type" value="{alert_type}">
            <select name="severity">
                <option value="">all severity</option>
                <option value="low" {"selected" if severity == "low" else ""}>low</option>
                <option value="medium" {"selected" if severity == "medium" else ""}>medium</option>
                <option value="high" {"selected" if severity == "high" else ""}>high</option>
                <option value="critical" {"selected" if severity == "critical" else ""}>critical</option>
            </select>
            <button type="submit">Filter</button>
        </form>
    </div>

    <table>
        <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Event ID</th>
            <th>Alert Type</th>
            <th>Severity</th>
            <th>Description</th>
        </tr>
        {table_rows}
    </table>
    """

    return page("Alerts", content)


@app.route("/export/events.csv")
def export_events_csv():
    conn = get_db()
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "source_host", "event_type", "severity", "message", "raw_log"])

    for r in rows:
        writer.writerow([
            r["id"], r["timestamp"], r["source_host"], r["event_type"],
            r["severity"], r["message"], r["raw_log"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"}
    )


@app.route("/export/alerts.csv")
def export_alerts_csv():
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "event_id", "alert_type", "severity", "description"])

    for r in rows:
        writer.writerow([
            r["id"], r["timestamp"], r["event_id"],
            r["alert_type"], r["severity"], r["description"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"}
    )


@app.route("/export/events.json")
def export_events_json():
    conn = get_db()
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    conn.close()

    data = [dict(r) for r in rows]
    return Response(json.dumps(data, indent=2), mimetype="application/json")


@app.route("/report/summary.txt")
def report_summary():
    conn = get_db()

    total_events = conn.execute("SELECT COUNT(*) AS total FROM events").fetchone()["total"]
    total_alerts = conn.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()["total"]

    event_types = conn.execute(
        "SELECT event_type, COUNT(*) AS total FROM events GROUP BY event_type ORDER BY total DESC"
    ).fetchall()

    alert_types = conn.execute(
        "SELECT alert_type, severity, COUNT(*) AS total FROM alerts GROUP BY alert_type, severity ORDER BY total DESC"
    ).fetchall()

    conn.close()

    lines = []
    lines.append("SIEM Report Summary")
    lines.append("===================")
    lines.append(f"Generated at: {now()}")
    lines.append("")
    lines.append(f"Total events: {total_events}")
    lines.append(f"Total alerts: {total_alerts}")
    lines.append("")
    lines.append("Event type summary:")
    for e in event_types:
        lines.append(f"- {e['event_type']}: {e['total']}")

    lines.append("")
    lines.append("Alert summary:")
    for a in alert_types:
        lines.append(f"- {a['alert_type']} ({a['severity']}): {a['total']}")

    lines.append("")
    lines.append("Testing scenarios:")
    lines.append("1. Failed/successful SSH login")
    lines.append("2. Failed sudo attempt")
    lines.append("3. User account creation/deletion")
    lines.append("4. Package installation")
    lines.append("5. Service stop/start")
    lines.append("6. File creation/modification/deletion")
    lines.append("7. Custom application log")

    return Response("\n".join(lines), mimetype="text/plain")


if __name__ == "__main__":
    init_db()
    print("SIEM Server running...")
    print("Dashboard: http://0.0.0.0:5000/dashboard")
    app.run(host="0.0.0.0", port=5000, debug=True)