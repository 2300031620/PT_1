# Windows Python Endpoint Agent (Watchdog File Monitor)

A lightweight endpoint monitoring agent designed for Windows endpoints to monitor user-specified folders in real time using the Python `watchdog` library.

The agent intercepts file system operations and streams structured event notifications to the FastAPI backend:
- `CREATE`
- `MODIFY`
- `DELETE`
- `MOVE/RENAME`

---

## 1. Prerequisites

- **Windows 10 / 11** or **Windows Server** (or macOS/Linux for development)
- **Python 3.8+** installed ([python.org](https://www.python.org/downloads/))
- Ensure Python and `pip` are added to your system `PATH`.

---

## 2. Installation

Open PowerShell or Command Prompt on your target machine:

```powershell
# Navigate to the endpoint_agent directory
cd endpoint_agent

# (Recommended) Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install required dependencies (watchdog and requests)
pip install -r requirements.txt
```

---

## 3. Configuration

### Monitored Folders
You can configure monitored directories in 3 ways:

1. **Command Line Argument (Highest Precedence):**
   ```powershell
   python agent.py --dirs "C:\Users\YourUser\Documents" "C:\TestFolder"
   ```

2. **Environment Variable:**
   ```powershell
   # In PowerShell
   $env:MONITORED_DIRS="C:\Users\YourUser\Documents,C:\TestFolder"
   python agent.py

   # In CMD
   set MONITORED_DIRS=C:\Users\YourUser\Documents,C:\TestFolder
   python agent.py
   ```

3. **In `config.py`:**
   Modify `DEFAULT_MONITORED_DIRS` directly in `config.py`:
   ```python
   DEFAULT_MONITORED_DIRS = [
       os.path.expanduser(r"~\Documents"),
       os.path.expanduser(r"~\Desktop"),
       os.path.expanduser(r"~\TestFolder"),
   ]
   ```

> **⚠️ SAFETY WARNING: Do NOT monitor the entire `C:\` drive.**
> Monitoring root drives like `C:\` captures hundreds of internal OS pagefile, swap, and logging events per second, causing severe system lag. The agent includes an automatic safety guard that disallows root drive paths. Always select specific subdirectories.

### Backend API URL
By default, events are sent to:
`http://localhost:8000/api`

To direct events to a remote server, Raspberry Pi, or custom port:
```powershell
python agent.py --backend "http://192.168.1.150:8000/api"
```
Or set the environment variable:
```powershell
$env:BACKEND_API_URL="http://192.168.1.150:8000/api"
```

---

## 4. Running the Agent

### Start the FastAPI Backend First (in a separate terminal)
```powershell
# From the project root
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Start the Endpoint Agent
```powershell
# In endpoint_agent folder
python agent.py
```

### Dry-Run Mode (Test without sending to backend)
```powershell
python agent.py --dry-run
```

---

## 5. Testing & Verification

We provide an automated test script (`test_events.py`) to verify that all 4 file operations are detected:

1. Keep the `agent.py` terminal running.
2. Open a **second** terminal window in `endpoint_agent/`:
   ```powershell
   python test_events.py
   ```
3. Press **Enter** to step through the automated sequence:
   - **Step 1: CREATE** (`audit_sample.txt` created)
   - **Step 2: MODIFY** (Appends text to `audit_sample.txt`)
   - **Step 3: MOVE/RENAME** (`audit_sample.txt` -> `archived_sample.txt`)
   - **Step 4: DELETE** (`archived_sample.txt` deleted)

### Expected Agent Output:
```text
========================================================================
    WINDOWS PYTHON ENDPOINT AGENT (WATCHDOG FILE MONITOR)
========================================================================
  Device Hostname : WINDOWS-PC-01
  IP Address      : 192.168.1.45
  Operating System: Windows 11 (AMD64)
  Backend API URL : http://localhost:8000/api (Dry Run: False)
  Monitored Folders:
    1. C:\Users\User\Documents
    2. C:\TestFolder
========================================================================
[+] Connected to FastAPI Backend at http://localhost:8000/api
[+] Actively monitoring: C:\TestFolder
[*] Watchdog observer started. Monitoring 1 directory trees.

[+] CREATE      | 14:22:01 | audit_sample.txt      | Path: C:\TestFolder\audit_sample.txt
[*] MODIFY      | 14:22:03 | audit_sample.txt      | Path: C:\TestFolder\audit_sample.txt
[>] MOVE/RENAME | 14:22:05 | audit_sample.txt -> archived_sample.txt | Path: C:\TestFolder\archived_sample.txt
[-] DELETE      | 14:22:07 | archived_sample.txt   | Path: C:\TestFolder\archived_sample.txt
```

---

## 6. Event Schema Sent to FastAPI

Each event is transmitted as a JSON `POST` request to `/api/events`:

```json
{
  "device_id": "WINDOWS-PC-01",
  "event_type": "CREATE",
  "file_path": "C:\\TestFolder\\audit_sample.txt",
  "old_path": null,
  "timestamp": "2026-09-20T11:22:01.456789+00:00",
  "is_protected": false,
  "is_suspicious": false,
  "details": "File created: audit_sample.txt",
  "process_name": "watchdog_agent"
}
```
For `MOVE/RENAME`:
```json
{
  "device_id": "WINDOWS-PC-01",
  "event_type": "MOVE/RENAME",
  "file_path": "C:\\TestFolder\\archived_sample.txt",
  "old_path": "C:\\TestFolder\\audit_sample.txt",
  "timestamp": "2026-09-20T11:22:05.123456+00:00",
  "is_protected": false,
  "is_suspicious": false,
  "details": "File moved/renamed: audit_sample.txt -> archived_sample.txt",
  "process_name": "watchdog_agent"
}
```
