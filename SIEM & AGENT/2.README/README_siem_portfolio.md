# Mini SIEM & Endpoint Log Monitoring System

## Overview

Mini SIEM & Endpoint Log Monitoring System is a cybersecurity portfolio project that demonstrates basic Security Information and Event Management (SIEM) functionality using Python. The system collects security events from an endpoint agent, sends the events to a SIEM server through an HTTP API, stores the data in SQLite, evaluates events using detection rules, generates alerts, and displays the results in a web dashboard.

This project was built in a local virtual lab environment for educational and portfolio purposes. It focuses on log monitoring, security event detection, alert generation, and security reporting.

## Objectives

The objectives of this project are:

- Build a simple SIEM server using Python and Flask.
- Create an endpoint agent to monitor Linux security logs.
- Collect and store endpoint events in a database.
- Detect suspicious activities using rule-based detection logic.
- Generate alerts based on event type and severity.
- Display events and alerts through a web dashboard.
- Export security data into CSV, JSON, and text report formats.
- Demonstrate basic SOC, log analysis, and detection engineering skills.

## Tools and Technologies

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Flask | Web dashboard and event receiver API |
| SQLite | Database for storing events and alerts |
| Requests | Sending HTTP POST events from agent to server |
| Watchdog | Monitoring file and directory changes |
| HTML/CSS | Dashboard interface |
| Ubuntu Server | Operating system for SIEM server and endpoint agent |
| VirtualBox | Local virtual lab environment |
| CSV/JSON/TXT | Export and reporting formats |

## Lab Environment

This project uses two virtual machines in a local lab environment.

| VM | Hostname | Role | OS | Example IP Address |
|---|---|---|---|---|
| VM 1 | siem-server | SIEM Server | Ubuntu Server | 192.168.56.3 |
| VM 2 | endpoint-agent | Monitored Endpoint | Ubuntu Server | 192.168.56.5 |

The endpoint agent monitors Linux logs and system activity, then sends events to the SIEM server using HTTP POST requests.

## System Architecture

```text
[Endpoint Agent VM]
        |
        | HTTP POST JSON Event
        v
[SIEM Server / Flask API]
        |
        v
[SQLite Database]
        |
        v
[Rule Engine]
        |
        v
[Alerts + Web Dashboard + Reports]
```

### Main Components

1. **Endpoint Agent**
   - Reads Linux log files.
   - Monitors SSH authentication activity.
   - Monitors sudo failure events.
   - Monitors package installation and removal logs.
   - Monitors file creation, modification, and deletion.
   - Monitors selected service status changes.
   - Sends security events to the SIEM server.

2. **SIEM Server**
   - Receives events from the endpoint agent through `/api/events`.
   - Stores events in SQLite.
   - Runs rule-based detection logic.
   - Generates alerts based on suspicious activity.
   - Provides a web dashboard for monitoring.
   - Supports CSV, JSON, and text report export.

3. **Database**
   - Stores raw events.
   - Stores generated alerts.
   - Supports filtering and reporting.

4. **Dashboard**
   - Displays event summary.
   - Displays security alerts.
   - Supports event and alert filtering.
   - Provides export options.

## Monitored Log Sources

The endpoint agent monitors the following Linux log sources:

```text
/var/log/auth.log
/var/log/syslog
/var/log/dpkg.log
/var/log/apt/history.log
journalctl -u ssh
/tmp/siem_watch
```

The `/tmp/siem_watch` directory is used to monitor file operations such as file creation, modification, and deletion.

## Detection Rules

| No | Detection Rule | Event Type | Severity | Description |
|---|---|---|---|---|
| 1 | Failed SSH Login | `failed_ssh` | High | Detects failed SSH login attempts. |
| 2 | Successful SSH Login | `successful_ssh` | Low | Detects successful SSH login activity. |
| 3 | Failed Sudo Attempt | `failed_sudo` | High | Detects failed sudo authentication attempts. |
| 4 | User Account Change | `user_created`, `user_deleted` | High | Detects user creation or deletion events. |
| 5 | Package Installation | `package_install` | Medium | Detects package installation activity. |
| 6 | Service Status Change | `service_started`, `service_stopped` | Medium | Detects service start or stop events. |
| 7 | File Operation | `file_created`, `file_modified`, `file_deleted` | Low/Medium | Detects file changes in the monitored directory. |
| 8 | Custom Security Log | `custom_log` | Medium | Detects custom application security logs. |
| 9 | High Severity Event | Any high severity event | High | Creates alert for high severity events. |
| 10 | Possible SSH Brute Force | `failed_ssh` | Critical | Detects 3 or more failed SSH attempts within 10 minutes. |

## Project Structure

```text
mini-siem-endpoint-log-monitoring/
│
├── src/
│   ├── SIEM.py
│   ├── agent.py
│   ├── database.sql
│   └── requirements.txt
│
├── docs/
│   ├── architecture-diagram.jpeg
│   └── data-flow-diagram.jpeg
│
├── screenshots/
│   ├── dashboard_home.png
│   ├── dashboard_events.png
│   ├── dashboard_alerts.png
│   ├── dashboard_filter.png
│   ├── event_01_failed_ssh.png
│   ├── event_02_successful_ssh.png
│   ├── event_03_failed_sudo.png
│   ├── event_04_user_account.png
│   ├── event_05_file_operation.png
│   └── event_06_service_or_custom_log.png
│
├── reports/
│   ├── events.csv
│   ├── alerts.csv
│   └── report_summary.txt
│
└── README.md
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/mini-siem-endpoint-log-monitoring.git
cd mini-siem-endpoint-log-monitoring
```

### 2. Install Dependencies

```bash
pip install -r src/requirements.txt
```

The required Python libraries are:

```text
Flask
requests
watchdog
```

### 3. Configure the Endpoint Agent

Open `src/agent.py` and adjust the SIEM server URL based on your lab IP address.

```python
SIEM_URL = "http://192.168.56.3:5000/api/events"
```

Change `192.168.56.3` to the IP address of your SIEM server.

## How to Run

### Run SIEM Server

On the SIEM server VM:

```bash
cd src
python3 SIEM.py
```

Then open the dashboard in a browser:

```text
http://127.0.0.1:5000/dashboard
```

If accessing from another VM or host machine, use the SIEM server IP address:

```text
http://192.168.56.3:5000/dashboard
```

### Run Endpoint Agent

On the endpoint agent VM:

```bash
cd src
sudo python3 agent.py
```

The agent should be run with `sudo` because some Linux log files require elevated permission to read.

## Testing Scenarios

The following scenarios can be used to test the SIEM detection rules.

### 1. Failed SSH Login

Try logging in through SSH using the wrong password.

Expected result:

```text
Event Type: failed_ssh
Alert Type: FAILED_SSH_LOGIN
Severity: high
```

### 2. Possible SSH Brute Force

Perform at least 3 failed SSH login attempts within 10 minutes.

Expected result:

```text
Event Type: failed_ssh
Alert Type: POSSIBLE_SSH_BRUTE_FORCE
Severity: critical
```

### 3. Successful SSH Login

Log in successfully through SSH.

Expected result:

```text
Event Type: successful_ssh
Alert Type: SUCCESSFUL_SSH_LOGIN
Severity: low
```

### 4. Failed Sudo Attempt

Run a sudo command and enter the wrong password.

Expected result:

```text
Event Type: failed_sudo
Alert Type: FAILED_SUDO_ATTEMPT
Severity: high
```

### 5. User Account Change

Create a test user:

```bash
sudo adduser testuser
```

Expected result:

```text
Event Type: user_created
Alert Type: USER_ACCOUNT_CHANGE
Severity: high
```

### 6. File Operation Monitoring

Create, modify, and delete a file in the monitored directory.

```bash
touch /tmp/siem_watch/test.txt
echo "test update" >> /tmp/siem_watch/test.txt
rm /tmp/siem_watch/test.txt
```

Expected result:

```text
Event Type: file_created
Event Type: file_modified
Event Type: file_deleted
Alert Type: FILE_OPERATION
```

### 7. Package Installation

Install a package on the endpoint machine.

```bash
sudo apt install tree
```

Expected result:

```text
Event Type: package_install
Alert Type: PACKAGE_INSTALLATION
Severity: medium
```

### 8. Service Status Change

Start or stop a monitored service.

```bash
sudo systemctl status ssh
```

Expected result:

```text
Event Type: service_started or service_stopped
Alert Type: SERVICE_STATUS_CHANGE
Severity: medium
```

## Dashboard Features

The SIEM dashboard includes:

- Total event summary.
- Total alert summary.
- Event list page.
- Alert list page.
- Severity-based filtering.
- Event type filtering.
- CSV export for events.
- CSV export for alerts.
- JSON export for events.
- Text-based summary report.

## Screenshots

### Dashboard Home

![Dashboard Home](screenshots/dashboard_home.png)

### Events Page

![Dashboard Events](screenshots/dashboard_events.png)

### Alerts Page

![Dashboard Alerts](screenshots/dashboard_alerts.png)

### Dashboard Filter

![Dashboard Filter](screenshots/dashboard_filter.png)

### Failed SSH Event

![Failed SSH Event](screenshots/event_01_failed_ssh.png)

### Successful SSH Event

![Successful SSH Event](screenshots/event_02_successful_ssh.png)

### Failed Sudo Event

![Failed Sudo Event](screenshots/event_03_failed_sudo.png)

### User Account Event

![User Account Event](screenshots/event_04_user_account.png)

### File Operation Event

![File Operation Event](screenshots/event_05_file_operation.png)

### Service or Custom Log Event

![Service or Custom Log Event](screenshots/event_06_service_or_custom_log.png)

## Result Summary

Based on the testing scenarios, the system successfully collected endpoint logs, classified security events, stored them in SQLite, generated alerts, and displayed the results through a web dashboard.

The implemented detection rules were able to identify:

- Failed SSH login attempts.
- Successful SSH login events.
- Possible SSH brute-force activity.
- Failed sudo attempts.
- User account changes.
- Package installation events.
- File creation, modification, and deletion events.
- Service status changes.
- Custom security log events.

The system also supports exporting events and alerts into CSV/JSON formats and generating a text-based summary report.

## Skills Demonstrated

This project demonstrates the following cybersecurity and technical skills:

- Security log monitoring.
- SOC analyst fundamentals.
- SIEM concept implementation.
- Endpoint event collection.
- Rule-based detection logic.
- Alert generation.
- Linux log analysis.
- Python scripting.
- Flask web development.
- SQLite database usage.
- Security reporting.
- Incident detection workflow.

## Limitations

This project is a simplified SIEM implementation for educational purposes. It does not include advanced enterprise SIEM features such as:

- Real-time distributed log ingestion at scale.
- Authentication and role-based access control.
- Advanced correlation rules.
- Threat intelligence integration.
- Log normalization using standard schemas.
- Encrypted communication between agent and server.
- Production-grade deployment and hardening.

## Future Improvements

Possible improvements for this project include:

- Add login authentication to the dashboard.
- Add HTTPS communication between agent and server.
- Add more advanced correlation rules.
- Add IP-based brute-force detection instead of hostname-only detection.
- Add email or Telegram alert notification.
- Add charts for alert trends.
- Add Docker support for easier deployment.
- Add more log source support such as Apache, Nginx, and firewall logs.

## Disclaimer

This project was created for educational and portfolio purposes only. All testing was conducted in a controlled local lab environment. This project should not be used to monitor systems without proper authorization.

## Conclusion

The Mini SIEM & Endpoint Log Monitoring System shows how basic SIEM concepts can be implemented using Python. Through this project, endpoint logs can be collected, classified, stored, analyzed, and converted into actionable alerts. This project demonstrates practical cybersecurity skills related to SOC monitoring, log analysis, detection engineering, and security reporting.
