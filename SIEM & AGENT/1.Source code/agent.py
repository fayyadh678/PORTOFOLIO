import os
import time
import socket
import threading
import subprocess
from datetime import datetime
from collections import deque

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# IP SIEM/API kamu yang sudah terbukti berhasil
SIEM_URL = "http://192.168.56.3:5000/api/events"

HOSTNAME = socket.gethostname()

LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/dpkg.log",
    "/var/log/apt/history.log"
]

WATCH_DIR = "/tmp/siem_watch"

# Jangan stop/start ssh kalau kamu login lewat SSH, nanti koneksi bisa putus.
SERVICE_NAME = "ssh"

# Biar event yang sama tidak terkirim berkali-kali
RECENT_EVENTS = deque(maxlen=100)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def already_sent(event_type, raw_log):
    """
    Anti duplikat.
    Sudah dibenerin: event_type ikut masuk key.
    Jadi file_created, file_modified, file_deleted untuk file yang sama
    tetap dianggap event berbeda.
    """
    key = f"{event_type}|{raw_log.strip()}"
    if key in RECENT_EVENTS:
        return True

    RECENT_EVENTS.append(key)
    return False


def send_event(event_type, severity, message, raw_log):
    if already_sent(event_type, raw_log):
        return

    data = {
        "timestamp": now(),
        "source_host": HOSTNAME,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "raw_log": raw_log
    }

    try:
        r = requests.post(SIEM_URL, json=data, timeout=5)
        print(f"[SEND] {event_type} | {severity} | status={r.status_code}")
        print(f"[RAW] {raw_log}")
    except Exception as e:
        print(f"[ERROR] Failed to send event: {e}")


def classify_log(line):
    lower = line.lower()

    # SSH failed login
    if (
        "sshd" in lower
        and (
            "failed password" in lower
            or "authentication failure" in lower
            or "invalid user" in lower
            or "maximum authentication attempts exceeded" in lower
            or "permission denied" in lower
            or "failed publickey" in lower
        )
    ):
        send_event(
            "failed_ssh",
            "high",
            "Failed SSH login detected",
            line
        )

    # SSH successful login
    elif (
        "sshd" in lower
        and (
            "accepted password" in lower
            or "accepted publickey" in lower
            or "session opened for user" in lower
        )
    ):
        send_event(
            "successful_ssh",
            "low",
            "Successful SSH login detected",
            line
        )

    # Failed sudo
    elif (
        "sudo" in lower
        and (
            "authentication failure" in lower
            or "incorrect password attempts" in lower
            or "password incorrect" in lower
        )
    ):
        send_event(
            "failed_sudo",
            "high",
            "Failed sudo attempt detected",
            line
        )

    # User creation
    elif (
        "new user" in lower
        or "useradd" in lower
        or "new account" in lower
    ):
        send_event(
            "user_created",
            "high",
            "User account creation detected",
            line
        )

    # User deletion
    elif (
        "delete user" in lower
        or "userdel" in lower
        or "removed user" in lower
    ):
        send_event(
            "user_deleted",
            "high",
            "User account deletion detected",
            line
        )

    # Package installation
    elif (
        " install " in lower
        or "status installed" in lower
        or "commandline: apt install" in lower
        or "commandline: apt-get install" in lower
    ):
        send_event(
            "package_install",
            "medium",
            "Package installation detected",
            line
        )

    # Package removal
    elif (
        " remove " in lower
        or "status not-installed" in lower
        or "commandline: apt remove" in lower
        or "commandline: apt-get remove" in lower
    ):
        send_event(
            "package_remove",
            "medium",
            "Package removal detected",
            line
        )

    # Service start
    elif "started " in lower:
        send_event(
            "service_started",
            "medium",
            "Service started detected from system log",
            line
        )

    # Service stop
    elif "stopped " in lower:
        send_event(
            "service_stopped",
            "medium",
            "Service stopped detected from system log",
            line
        )

    # Custom application log
    elif (
        "custom security event" in lower
        or "custom_app" in lower
        or "uas_siem_test" in lower
    ):
        send_event(
            "custom_log",
            "medium",
            "Custom application security log detected",
            line
        )


def tail_file(path):
    print(f"[LOG] Monitoring {path}")

    while not os.path.exists(path):
        print(f"[WAIT] Log file not found yet: {path}")
        time.sleep(5)

    try:
        with open(path, "r", errors="ignore") as f:
            # Mulai baca dari akhir file.
            # Agent hanya baca log baru setelah agent running.
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(1)
                    continue

                line = line.strip()

                if line:
                    print(f"[READ] {path}: {line}")
                    classify_log(line)

    except PermissionError:
        print(f"[ERROR] Permission denied reading {path}. Run agent with sudo.")
    except Exception as e:
        print(f"[ERROR] Problem reading {path}: {e}")


def monitor_ssh_journal():
    """
    Tambahan:
    Di beberapa Ubuntu, log SSH kadang masuk journalctl.
    Jadi ini ikut monitor journal SSH juga.
    """
    print("[JOURNAL] Monitoring ssh journal logs")

    try:
        process = subprocess.Popen(
            ["journalctl", "-u", "ssh", "-f", "-n", "0", "-o", "short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        while True:
            line = process.stdout.readline()

            if not line:
                time.sleep(1)
                continue

            line = line.strip()

            if line:
                print(f"[JOURNAL READ] {line}")
                classify_log(line)

    except Exception as e:
        print(f"[ERROR] Problem monitoring journalctl ssh: {e}")


class WatchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            send_event(
                "file_created",
                "low",
                f"File created: {event.src_path}",
                event.src_path
            )

    def on_modified(self, event):
        if not event.is_directory:
            send_event(
                "file_modified",
                "low",
                f"File modified: {event.src_path}",
                event.src_path
            )

    def on_deleted(self, event):
        if not event.is_directory:
            send_event(
                "file_deleted",
                "medium",
                f"File deleted: {event.src_path}",
                event.src_path
            )


def monitor_directory():
    os.makedirs(WATCH_DIR, exist_ok=True)
    print(f"[FILE] Monitoring directory {WATCH_DIR}")

    observer = Observer()
    observer.schedule(WatchHandler(), WATCH_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


def get_service_status(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def monitor_service():
    last_status = get_service_status(SERVICE_NAME)
    print(f"[SERVICE] Monitoring {SERVICE_NAME}, initial status: {last_status}")

    while True:
        time.sleep(5)
        current_status = get_service_status(SERVICE_NAME)

        if current_status != last_status:
            if current_status == "active":
                send_event(
                    "service_started",
                    "medium",
                    f"Service {SERVICE_NAME} started",
                    f"{SERVICE_NAME}: {last_status} -> {current_status}"
                )
            else:
                send_event(
                    "service_stopped",
                    "medium",
                    f"Service {SERVICE_NAME} stopped or changed status",
                    f"{SERVICE_NAME}: {last_status} -> {current_status}"
                )

            last_status = current_status


def main():
    print("Endpoint Agent Started")
    print(f"Hostname: {HOSTNAME}")
    print(f"SIEM URL: {SIEM_URL}")
    print("Press CTRL+C to stop")

    threads = []

    for log_file in LOG_FILES:
        t = threading.Thread(target=tail_file, args=(log_file,), daemon=True)
        t.start()
        threads.append(t)

    t_journal = threading.Thread(target=monitor_ssh_journal, daemon=True)
    t_journal.start()
    threads.append(t_journal)

    t_file = threading.Thread(target=monitor_directory, daemon=True)
    t_file.start()
    threads.append(t_file)

    t_service = threading.Thread(target=monitor_service, daemon=True)
    t_service.start()
    threads.append(t_service)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Agent stopped")


if __name__ == "__main__":
    main()