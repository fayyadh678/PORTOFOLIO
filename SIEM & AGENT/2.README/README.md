

# 2. Penjelasan System Design

## 2.1 Arsitektur Sistem dan Teknologi yang Digunakan

Project ini merupakan implementasi sederhana dari Security Information and Event Management atau SIEM menggunakan Python. Sistem SIEM ini dirancang untuk mengumpulkan event keamanan dari endpoint yang dimonitor, mengirim event tersebut ke server, menyimpan data ke database, menganalisis event menggunakan rule engine sederhana, menghasilkan alert, dan menampilkan hasilnya melalui web dashboard.

Sistem terdiri dari dua virtual machine utama:

1. **VM1 sebagai SIEM Server**

   * Menerima event dari endpoint agent melalui HTTP POST.
   * Menyimpan event ke database SQLite.
   * Menjalankan rule engine untuk mendeteksi aktivitas mencurigakan.
   * Menghasilkan alert.
   * Menampilkan dashboard web.
   * Menyediakan fitur export data ke CSV dan report summary.

2. **VM2 sebagai Endpoint Agent**

   * Membaca log sistem seperti `/var/log/auth.log`, `/var/log/syslog`, `/var/log/dpkg.log`, dan `/var/log/apt/history.log`.
   * Mendeteksi penambahan baris baru pada file log.
   * Mengklasifikasikan log menjadi event type tertentu.
   * Memonitor perubahan file pada direktori tertentu.
   * Mengecek status service tertentu.
   * Mengirim event ke SIEM Server menggunakan HTTP POST dalam format JSON.

Teknologi yang digunakan:

| Teknologi            | Fungsi                                                       |
| -------------------- | ------------------------------------------------------------ |
| VirtualBox           | Menjalankan VM1 dan VM2                                      |
| Ubuntu Server        | Sistem operasi untuk SIEM Server dan Endpoint Agent          |
| Python               | Bahasa pemrograman utama                                     |
| Flask                | Framework untuk membuat Event Receiver API dan Web Dashboard |
| SQLite               | Database untuk menyimpan events dan alerts                   |
| Requests             | Library Python untuk mengirim HTTP POST dari agent ke server |
| Watchdog             | Library Python untuk memonitor perubahan file/direktori      |
| HTML/CSS             | Tampilan dashboard SIEM                                      |
| CSV/JSON/Text Report | Format reporting dan export data                             |

Arsitektur sistem secara umum:

```text
[VM2 Endpoint Agent]
        |
        | HTTP POST JSON Event
        v
[VM1 SIEM Server]
        |
        v
[SQLite Database]
        |
        v
[Rule Engine]
        |
        v
[Alerts + Web Dashboard + Reporting]
```

---

## 2.2 Topologi dan Spesifikasi VM

Project ini menggunakan dua virtual machine dengan fungsi berbeda.

| VM  | Hostname       | Fungsi                  | OS            | IP Address     | Spesifikasi                        |
| --- | -------------- | ----------------------- | ------------- | -------------- | ---------------------------------- |
| VM1 | siem-server    | SIEM Server             | Ubuntu Server | 192.168.56.3 | 2-4 CPU, 2-3 GB RAM, 25 GB Disk    |
| VM2 | endpoint-agent | Endpoint yang dimonitor | Ubuntu Server | 192.168.56.5 | 1-2 CPU, 1-2 GB RAM, 20-25 GB Disk |

Keterangan:

* VM1 digunakan sebagai server utama SIEM.
* VM2 digunakan sebagai endpoint yang menghasilkan event keamanan.
* VM2 mengirim event ke VM1 melalui jaringan menggunakan HTTP POST.
* Dashboard SIEM diakses melalui browser menggunakan alamat:


http://127.0.0.1:5000/dashboard


Topologi jaringan:

Laptop / Browser
      |
      | akses dashboard
      v
VM1 - SIEM Server
IP: 192.168.56.3
Port: 5000
      ^
      | HTTP POST JSON
      |
VM2 - Endpoint Agent
IP: 192.168.56.5
```

---

## 2.3 Aliran Data antara Agent, Server, Database, Rule Engine, dan Dashboard

Aliran data sistem SIEM ini berjalan sebagai berikut:

1. **Endpoint menghasilkan log**

   * VM2 menghasilkan aktivitas sistem seperti login SSH, failed login, sudo attempt, perubahan file, instalasi package, perubahan service, dan custom log.
   * Log berasal dari file seperti:

     * `/var/log/auth.log`
     * `/var/log/syslog`
     * `/var/log/dpkg.log`
     * `/var/log/apt/history.log`

2. **Agent membaca log**

   * Endpoint Agent membaca file log secara real-time.
   * Agent mendeteksi adanya baris baru pada log.
   * Agent juga memonitor direktori `/tmp/siem_watch` untuk mendeteksi file dibuat, diubah, atau dihapus.
   * Agent mengecek status service tertentu, misalnya service `ssh`.

3. **Agent mengklasifikasikan event**

   * Log yang terbaca akan diklasifikasikan menjadi event type.
   * Contoh event type:

     * `failed_ssh`
     * `successful_ssh`
     * `failed_sudo`
     * `user_created`
     * `user_deleted`
     * `package_install`
     * `service_started`
     * `service_stopped`
     * `file_created`
     * `file_modified`
     * `file_deleted`
     * `custom_log`

4. **Agent mengirim event ke server**

   * Event dikirim dari VM2 ke VM1 menggunakan HTTP POST.
   * Format data yang dikirim adalah JSON.
   * Endpoint API yang digunakan:

```text
POST /api/events
```

Contoh format JSON event:

```json
{
  "timestamp": "2026-06-20 10:00:00",
  "source_host": "endpoint-agent",
  "event_type": "failed_ssh",
  "severity": "high",
  "message": "Failed SSH login detected",
  "raw_log": "Failed password for invalid user test from 192.168.56.1 port 54321 ssh2"
}
```

5. **SIEM Server menerima event**

   * Flask server di VM1 menerima JSON event melalui endpoint `/api/events`.
   * Server melakukan validasi data.
   * Jika data valid, event disimpan ke database SQLite.

6. **Database menyimpan event**

   * Event disimpan ke tabel `events`.
   * Data yang disimpan meliputi timestamp, source host, event type, severity, message, dan raw log.

7. **Rule Engine menganalisis event**

   * Setelah event disimpan, rule engine memeriksa event tersebut.
   * Jika event cocok dengan rule tertentu, sistem akan menghasilkan alert.
   * Alert disimpan ke tabel `alerts`.

8. **Dashboard menampilkan data**

   * Dashboard menampilkan summary card seperti total events, total alerts, high alerts, dan critical alerts.
   * Halaman events menampilkan daftar semua event.
   * Halaman alerts menampilkan daftar semua alert.
   * Dashboard juga menyediakan fitur filter berdasarkan event type, severity, dan source host.

9. **Reporting**

   * Data event dan alert dapat diekspor menjadi CSV.
   * Sistem juga menyediakan ringkasan dalam bentuk text report.

Aliran data lengkap:

```text
Log File / File Monitor / Service Monitor
        |
        v
Endpoint Agent
        |
        v
Event Classification
        |
        v
HTTP POST JSON
        |
        v
Flask Event Receiver API
        |
        v
SQLite Database
        |
        v
Rule Engine
        |
        v
Alert Generator
        |
        v
Web Dashboard + Export Report
```

---

## 2.4 Desain Database

Database yang digunakan adalah SQLite. Database menyimpan dua jenis data utama, yaitu events dan alerts.

### 2.4.1 Tabel Events

Tabel `events` digunakan untuk menyimpan semua event yang diterima dari endpoint agent.

Struktur tabel:

```sql
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_host TEXT,
    event_type TEXT,
    severity TEXT,
    message TEXT,
    raw_log TEXT
);
```

Penjelasan kolom:

| Kolom       | Tipe Data | Keterangan                       |
| ----------- | --------- | -------------------------------- |
| id          | INTEGER   | Primary key dan auto increment   |
| timestamp   | TEXT      | Waktu event terjadi              |
| source_host | TEXT      | Hostname endpoint pengirim event |
| event_type  | TEXT      | Jenis event yang terdeteksi      |
| severity    | TEXT      | Tingkat risiko event             |
| message     | TEXT      | Pesan ringkas event              |
| raw_log     | TEXT      | Log asli dari endpoint           |

Contoh isi tabel events:

| id | timestamp           | source_host    | event_type     | severity | message                                |
| -- | ------------------- | -------------- | -------------- | -------- | -------------------------------------- |
| 1  | 2026-06-20 10:00:00 | endpoint-agent | failed_ssh     | high     | Failed SSH login detected              |
| 2  | 2026-06-20 10:05:00 | endpoint-agent | successful_ssh | low      | Successful SSH login detected          |
| 3  | 2026-06-20 10:10:00 | endpoint-agent | file_created   | low      | File created: /tmp/siem_watch/test.txt |

---

### 2.4.2 Tabel Alerts

Tabel `alerts` digunakan untuk menyimpan alert yang dihasilkan oleh rule engine.

Struktur tabel:

```sql
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_id INTEGER,
    alert_type TEXT,
    severity TEXT,
    description TEXT,
    FOREIGN KEY(event_id) REFERENCES events(id)
);
```

Penjelasan kolom:

| Kolom       | Tipe Data | Keterangan                     |
| ----------- | --------- | ------------------------------ |
| id          | INTEGER   | Primary key dan auto increment |
| timestamp   | TEXT      | Waktu alert dibuat             |
| event_id    | INTEGER   | ID event yang memicu alert     |
| alert_type  | TEXT      | Jenis alert                    |
| severity    | TEXT      | Tingkat risiko alert           |
| description | TEXT      | Deskripsi alert                |

Contoh isi tabel alerts:

| id | timestamp           | event_id | alert_type               | severity | description                                   |
| -- | ------------------- | -------- | ------------------------ | -------- | --------------------------------------------- |
| 1  | 2026-06-20 10:00:05 | 1        | FAILED_SSH_LOGIN         | high     | Failed SSH login detected from endpoint-agent |
| 2  | 2026-06-20 10:15:00 | 5        | POSSIBLE_SSH_BRUTE_FORCE | critical | Possible SSH brute force detected             |

---

## 2.5 Detection Rule

Detection rule digunakan untuk menganalisis event dan menghasilkan alert secara otomatis. Rule engine bekerja dengan memeriksa nilai `event_type`, `severity`, `message`, dan `raw_log`.

Daftar detection rule:

## Detection Rule

Tabel berikut menjelaskan daftar rule deteksi yang digunakan pada sistem SIEM. Rule digunakan untuk mengidentifikasi aktivitas mencurigakan berdasarkan `event_type`, isi `raw_log`, serta tingkat keparahan event.

## Detection Rule

Sistem SIEM menggunakan beberapa detection rule untuk mengidentifikasi aktivitas mencurigakan dari event yang dikirim oleh endpoint agent. Rule dibuat berdasarkan `event_type`, isi `raw_log`, dan nilai `severity`.

### 1. Failed SSH Login

* **Kondisi Deteksi:** Event type `failed_ssh` atau raw log mengandung `Failed password`
* **Alert Type:** `FAILED_SSH_LOGIN`
* **Severity:** `high`

### 2. Successful SSH Login

* **Kondisi Deteksi:** Event type `successful_ssh` atau raw log mengandung `Accepted password`
* **Alert Type:** `SUCCESSFUL_SSH_LOGIN`
* **Severity:** `low`

### 3. Failed Sudo Attempt

* **Kondisi Deteksi:** Event type `failed_sudo` atau raw log mengandung `incorrect password`
* **Alert Type:** `FAILED_SUDO_ATTEMPT`
* **Severity:** `high`

### 4. User Account Creation

* **Kondisi Deteksi:** Event type `user_created` atau raw log mengandung `useradd` / `new user`
* **Alert Type:** `USER_ACCOUNT_CHANGE`
* **Severity:** `high`

### 5. User Account Deletion

* **Kondisi Deteksi:** Event type `user_deleted` atau raw log mengandung `userdel` / `delete user`
* **Alert Type:** `USER_ACCOUNT_CHANGE`
* **Severity:** `high`

### 6. Package Installation

* **Kondisi Deteksi:** Event type `package_install` atau log apt/dpkg menunjukkan instalasi package
* **Alert Type:** `PACKAGE_INSTALLATION`
* **Severity:** `medium`

### 7. Service Started

* **Kondisi Deteksi:** Event type `service_started`
* **Alert Type:** `SERVICE_STATUS_CHANGE`
* **Severity:** `medium`

### 8. Service Stopped

* **Kondisi Deteksi:** Event type `service_stopped`
* **Alert Type:** `SERVICE_STATUS_CHANGE`
* **Severity:** `medium`

### 9. File Created

* **Kondisi Deteksi:** Event type `file_created`
* **Alert Type:** `FILE_OPERATION`
* **Severity:** `low`

### 10. File Modified

* **Kondisi Deteksi:** Event type `file_modified`
* **Alert Type:** `FILE_OPERATION`
* **Severity:** `low`

### 11. File Deleted

* **Kondisi Deteksi:** Event type `file_deleted`
* **Alert Type:** `FILE_OPERATION`
* **Severity:** `medium`

### 12. Custom Application Log

* **Kondisi Deteksi:** Event type `custom_log`
* **Alert Type:** `CUSTOM_SECURITY_LOG`
* **Severity:** `medium`

### 13. SSH Brute Force

* **Kondisi Deteksi:** Terdapat minimal 3 event `failed_ssh` dalam waktu 10 menit dari endpoint yang sama
* **Alert Type:** `POSSIBLE_SSH_BRUTE_FORCE`
* **Severity:** `critical`

### 14. High Severity Event

* **Kondisi Deteksi:** Event memiliki severity `high`
* **Alert Type:** `HIGH_SEVERITY_EVENT`
* **Severity:** `high`

Detection rule tersebut digunakan oleh SIEM server untuk membuat alert secara otomatis ketika event yang diterima memenuhi kondisi tertentu. Dengan rule ini, sistem dapat mendeteksi aktivitas seperti gagal login SSH, login SSH berhasil, percobaan sudo gagal, perubahan akun pengguna, instalasi package, perubahan service, operasi file, custom log, indikasi brute force SSH, dan event dengan severity tinggi.



Contoh logika rule:

```text
Jika event_type = failed_ssh
Maka sistem membuat alert FAILED_SSH_LOGIN dengan severity high.
```

```text
Jika terdapat 3 event failed_ssh dalam waktu 10 menit
Maka sistem membuat alert POSSIBLE_SSH_BRUTE_FORCE dengan severity critical.
```

---

# 3. Penjelasan Hasil Implementasi

## 3.1 Aplikasi SIEM

Aplikasi SIEM berjalan pada VM1 dengan hostname `siem-server`. Aplikasi ini dibuat menggunakan Python Flask dan SQLite.

Fitur yang berhasil diimplementasikan pada SIEM Server:

1. **Event Receiver API**

   * Endpoint `/api/events` menerima event dalam format JSON.
   * Event dikirim oleh agent menggunakan HTTP POST.
   * Server mengembalikan response JSON jika event berhasil diterima.

2. **Database SQLite**

   * Event disimpan ke tabel `events`.
   * Alert disimpan ke tabel `alerts`.
   * Database menggunakan file `siem.db`.

3. **Rule Engine**

   * Rule engine berjalan setelah event diterima.
   * Rule engine mengecek apakah event cocok dengan detection rule.
   * Jika cocok, alert akan dibuat secara otomatis.

4. **Web Dashboard**

   * Dashboard dapat diakses melalui browser.
   * Dashboard menampilkan summary card seperti:

     * Total events
     * Total alerts
     * High alerts
     * Critical alerts
   * Dashboard juga menampilkan recent events dan recent alerts.

5. **Halaman Events**

   * Menampilkan daftar event yang diterima.
   * Menampilkan timestamp, source host, event type, severity, message, dan raw log.
   * Mendukung filter berdasarkan event type, severity, dan source host.

6. **Halaman Alerts**

   * Menampilkan daftar alert yang dihasilkan oleh rule engine.
   * Menampilkan timestamp, event ID, alert type, severity, dan description.
   * Mendukung filter berdasarkan alert type dan severity.

7. **Reporting**

   * Sistem menyediakan export `events.csv`.
   * Sistem menyediakan export `alerts.csv`.
   * Sistem menyediakan `report_summary.txt`.
   * Report berisi total events, total alerts, ringkasan event type, dan ringkasan alert type.

Endpoint yang tersedia pada SIEM Server:

| Endpoint              | Method | Fungsi                             |
| --------------------- | ------ | ---------------------------------- |
| `/api/events`         | POST   | Menerima event dari endpoint agent |
| `/dashboard`          | GET    | Menampilkan dashboard utama        |
| `/events`             | GET    | Menampilkan daftar event           |
| `/alerts`             | GET    | Menampilkan daftar alert           |
| `/export/events.csv`  | GET    | Export events ke CSV               |
| `/export/alerts.csv`  | GET    | Export alerts ke CSV               |
| `/export/events.json` | GET    | Export events ke JSON              |
| `/report/summary.txt` | GET    | Menampilkan report summary         |

---

## 3.2 Endpoint Agent

Endpoint Agent berjalan pada VM2 dengan hostname `endpoint-agent`. Agent dibuat menggunakan Python dan bertugas untuk memonitor aktivitas lokal endpoint.

Fitur yang berhasil diimplementasikan pada Endpoint Agent:

1. **Log Monitoring**

   * Agent membaca log dari beberapa file:

     * `/var/log/auth.log`
     * `/var/log/syslog`
     * `/var/log/dpkg.log`
     * `/var/log/apt/history.log`
   * Agent mendeteksi penambahan baris baru pada log.

2. **Event Classification**

   * Agent mengklasifikasikan log menjadi event type.
   * Contoh klasifikasi:

     * Log `Failed password` diklasifikasikan sebagai `failed_ssh`.
     * Log `Accepted password` diklasifikasikan sebagai `successful_ssh`.
     * Log sudo gagal diklasifikasikan sebagai `failed_sudo`.
     * Log instalasi package diklasifikasikan sebagai `package_install`.

3. **File Monitoring**

   * Agent memonitor direktori `/tmp/siem_watch`.
   * Agent mendeteksi file dibuat, diubah, atau dihapus.
   * Event yang dihasilkan:

     * `file_created`
     * `file_modified`
     * `file_deleted`

4. **Service Monitoring**

   * Agent mengecek status service tertentu, misalnya service `ssh`.
   * Jika service berubah status, agent mengirim event:

     * `service_started`
     * `service_stopped`

5. **HTTP POST Sender**

   * Agent mengirim event ke SIEM Server menggunakan library `requests`.
   * Event dikirim ke endpoint:

```text
http://127.0.0.1:5000/events
```

6. **Format Event**

   * Event dikirim menggunakan JSON dengan field:

     * timestamp
     * source_host
     * event_type
     * severity
     * message
     * raw_log

Contoh event yang dikirim agent:

```json
{
  "timestamp": "2026-06-20 10:00:00",
  "source_host": "endpoint-agent",
  "event_type": "file_created",
  "severity": "low",
  "message": "File created: /tmp/siem_watch/test.txt",
  "raw_log": "/tmp/siem_watch/test.txt"
}
```

---

# 4. Penjelasan Hasil Pengujian

## 4.1 Testing Environment

Pengujian dilakukan menggunakan dua virtual machine Ubuntu Server pada VirtualBox.

| Komponen           | Keterangan                               |
| ------------------ | ---------------------------------------- |
| Hypervisor         | VirtualBox                               |
| VM1                | siem-server                              |
| VM2                | endpoint-agent                           |
| OS VM1             | Ubuntu Server                            |
| OS VM2             | Ubuntu Server                            |
| Bahasa Pemrograman | Python                                   |
| Framework          | Flask                                    |
| Database           | SQLite                                   |
| Network            | NAT dan Host-only Adapter                |
| Browser Dashboard  | Google Chrome / Microsoft Edge / Firefox |
| Port SIEM          | 5000                                     |

Spesifikasi VM:

| VM  | CPU      | RAM    | Disk     | Fungsi         |
| --- | -------- | ------ | -------- | -------------- |
| VM1 | 2-4 Core | 2-3 GB | 25 GB    | SIEM Server    |
| VM2 | 1-2 Core | 1-2 GB | 20-25 GB | Endpoint Agent |

---

## 4.2 Cara Instalasi dan Menjalankan Pengujian

### 4.2.1 Instalasi SIEM Server pada VM1

Langkah instalasi pada VM1:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv sqlite3 curl git zip openssh-server -y
```

Membuat folder project:

```bash
cd ~
mkdir siem-project
cd siem-project
mkdir -p server agent diagrams screenshots
python3 -m venv venv
source venv/bin/activate
pip install flask requests watchdog
pip freeze > requirements.txt
```

Menjalankan SIEM Server:

```bash
cd ~/siem-project
source venv/bin/activate
python3 server/app.py
```

Dashboard dibuka melalui browser:

```text
http://127.0.0.1:5000/dashboard
```

---

### 4.2.2 Instalasi Endpoint Agent pada VM2

Langkah instalasi pada VM2:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv curl git openssh-server rsyslog -y
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

Membuat folder agent:

```bash
cd ~
mkdir siem-agent
cd siem-agent
python3 -m venv venv
source venv/bin/activate
pip install requests watchdog
pip freeze > requirements.txt
```

Menjalankan agent:

```bash
cd ~/siem-agent
sudo ./venv/bin/python agent.py
```

---

### 4.2.3 Pengujian Koneksi Agent ke Server

Sebelum pengujian skenario, dilakukan test pengiriman event manual dari VM2 ke VM1.

Command:

```bash
curl -X POST http://127.0.0.1:5000/dashboard \
-H "Content-Type: application/json" \
-d '{
  "source_host": "endpoint-agent",
  "event_type": "test_event",
  "severity": "low",
  "message": "Test event from endpoint",
  "raw_log": "manual curl test"
}'
```

Hasil yang diharapkan:

```json
{
  "event_id": 1,
  "message": "Event received",
  "status": "success"
}
```

Jika event muncul pada halaman `/events`, maka koneksi antara VM2 dan VM1 berhasil.

---

## 4.3 Skenario Pengujian

### 4.3.1 Failed SSH Login

Tujuan pengujian:

Mendeteksi percobaan login SSH yang gagal.

Langkah pengujian:

```bash
ssh endpoint@192.168.56.5
```

Masukkan password yang salah beberapa kali.

Hasil yang diharapkan:

* Agent membaca log `Failed password`.
* Agent mengirim event `failed_ssh`.
* SIEM Server menyimpan event.
* Rule engine menghasilkan alert `FAILED_SSH_LOGIN`.
* Event muncul pada halaman events.
* Alert muncul pada halaman alerts.

Screenshot:

```text
event_01_failed_ssh.png
```

---

### 4.3.2 Successful SSH Login

Tujuan pengujian:

Mendeteksi login SSH yang berhasil.

Langkah pengujian:

```bash
ssh endpoint@192.168.56.5
```

Masukkan password yang benar.

Hasil yang diharapkan:

* Agent membaca log `Accepted password`.
* Agent mengirim event `successful_ssh`.
* Event tersimpan ke database.
* Event muncul pada dashboard.

Screenshot:

```text
event_02_successful_ssh.png
```

---

### 4.3.3 Failed Sudo Attempt

Tujuan pengujian:

Mendeteksi percobaan penggunaan sudo dengan password salah.

Langkah pengujian:

```bash
sudo -k
sudo ls
```

Masukkan password yang salah.

Hasil yang diharapkan:

* Agent membaca log authentication failure.
* Agent mengirim event `failed_sudo`.
* Rule engine menghasilkan alert `FAILED_SUDO_ATTEMPT`.
* Event dan alert muncul di dashboard.

Screenshot:

```text
event_03_failed_sudo.png
```

---

### 4.3.4 User Account Creation dan Deletion

Tujuan pengujian:

Mendeteksi pembuatan dan penghapusan user account.

Langkah pengujian:

```bash
sudo useradd -m testuser
sudo userdel -r testuser
```

Hasil yang diharapkan:

* Agent membaca log user creation dan deletion.
* Agent mengirim event `user_created` dan `user_deleted`.
* Rule engine menghasilkan alert `USER_ACCOUNT_CHANGE`.
* Event muncul di halaman events.

Screenshot:

```text
event_04_user_account.png
```

---

### 4.3.5 Package Installation

Tujuan pengujian:

Mendeteksi instalasi package pada endpoint.

Langkah pengujian:

```bash
sudo apt install tree -y
```

Hasil yang diharapkan:

* Agent membaca log apt/dpkg.
* Agent mengirim event `package_install`.
* Rule engine menghasilkan alert `PACKAGE_INSTALLATION`.
* Event muncul pada halaman events.

---

### 4.3.6 Service Stop dan Start

Tujuan pengujian:

Mendeteksi perubahan status service.

Langkah pengujian:

```bash
sudo systemctl stop ssh
sudo systemctl start ssh
```

Alternatif jika sedang login melalui SSH:

```bash
logger "UAS_SIEM_TEST custom security event from endpoint-agent"
```

Hasil yang diharapkan:

* Agent mendeteksi perubahan status service.
* Agent mengirim event `service_stopped` atau `service_started`.
* Jika menggunakan custom log, agent mengirim event `custom_log`.
* Rule engine menghasilkan alert `SERVICE_STATUS_CHANGE` atau `CUSTOM_SECURITY_LOG`.

Screenshot:

```text
event_06_service_or_custom_log.png
```

---

### 4.3.7 File Creation, Modification, dan Deletion

Tujuan pengujian:

Mendeteksi perubahan file pada direktori yang dimonitor.

Langkah pengujian:

```bash
mkdir -p /tmp/siem_watch
touch /tmp/siem_watch/test.txt
echo "hello SIEM" >> /tmp/siem_watch/test.txt
rm /tmp/siem_watch/test.txt
```

Hasil yang diharapkan:

* Agent mendeteksi file dibuat.
* Agent mendeteksi file diubah.
* Agent mendeteksi file dihapus.
* Event yang muncul:

  * `file_created`
  * `file_modified`
  * `file_deleted`
* Rule engine menghasilkan alert `FILE_OPERATION`.

Screenshot:

```text
event_05_file_operation.png
```

---

### 4.3.8 Dashboard Filter

Tujuan pengujian:

Menguji fitur filter pada dashboard events.

Langkah pengujian:

1. Buka halaman:

```text
http://127.0.0.1:5000/dashboard
```

2. Isi filter event type:

```text
failed_ssh
```

3. Klik tombol Filter.

Hasil yang diharapkan:

* Dashboard hanya menampilkan event dengan type `failed_ssh`.

Screenshot:

```text
dashboard_filter.png
```

---

## 4.4 Rangkuman Hasil Pengujian

Berdasarkan hasil pengujian, aplikasi SIEM berhasil menjalankan fungsi utama sebagai berikut:

| No | Skenario               | Event Type                        | Status   |
| -- | ---------------------- | --------------------------------- | -------- |
| 1  | Failed SSH Login       | failed_ssh                        | Berhasil |
| 2  | Successful SSH Login   | successful_ssh                    | Berhasil |
| 3  | Failed Sudo Attempt    | failed_sudo                       | Berhasil |
| 4  | User Account Creation  | user_created                      | Berhasil |
| 5  | User Account Deletion  | user_deleted                      | Berhasil |
| 6  | Package Installation   | package_install                   | Berhasil |
| 7  | Service Stop/Start     | service_stopped / service_started | Berhasil |
| 8  | File Creation          | file_created                      | Berhasil |
| 9  | File Modification      | file_modified                     | Berhasil |
| 10 | File Deletion          | file_deleted                      | Berhasil |
| 11 | Custom Application Log | custom_log                        | Berhasil |
| 12 | Dashboard Filter       | filter event type/severity        | Berhasil |
| 13 | Export CSV             | events.csv dan alerts.csv         | Berhasil |
| 14 | Report Summary         | report_summary.txt                | Berhasil |

Kesimpulan pengujian:

Aplikasi SIEM yang dibuat berhasil menerima event dari endpoint-agent, menyimpan event ke SQLite database, menganalisis event menggunakan rule engine sederhana, menghasilkan alert, menampilkan hasil pada dashboard web, menyediakan fitur filter, dan menghasilkan report dalam bentuk CSV serta text summary.

File hasil pengujian yang dikumpulkan:

```text
events.csv
alerts.csv
report_summary.txt
```

Screenshot hasil pengujian yang dikumpulkan:

```text
dashboard_home.png
dashboard_events.png
dashboard_alerts.png
dashboard_filter.png
event_01_failed_ssh.png
event_02_successful_ssh.png
event_03_failed_sudo.png
event_04_user_account.png
event_05_file_operation.png
event_06_service_or_custom_log.png
```

---

# 5. Kesimpulan

Project ini berhasil mengimplementasikan SIEM sederhana menggunakan Python. Sistem terdiri dari SIEM Server dan Endpoint Agent. Endpoint Agent dapat membaca log, memonitor file, mengecek service, dan mengirim event ke server. SIEM Server dapat menerima event, menyimpan ke SQLite, menjalankan detection rule, menghasilkan alert, menampilkan dashboard, serta melakukan export report.

Dengan adanya project ini, proses monitoring keamanan pada endpoint dapat dilakukan secara terpusat melalui dashboard SIEM.
