# Ransomware Detection and Prevention System
An academic cybersecurity project demonstrating lightweight heuristic detection and containment of ransomware-like file-system behavior on Windows endpoints.

---

## Architecture Overview

```
Windows Computer (Target Endpoint)
       ↓
Python Endpoint Agent (watchdog file-system observer)
       ↓
Local Ransomware Detection & Rule-Based Scoring Engine
       ↓
Backend API (FastAPI) / (Optional Future Raspberry Pi Local Server)
       ↓
Firebase (Firestore Database & Auth)
       ↓
React Web Dashboard
```

---

## 1. How to Install

### Prerequisites
- **Node.js** v18+ and **npm** / **bun**
- **Python** 3.9+ and **pip**
- A modern web browser

### Clone & Dependencies Setup
```bash
# 1. Install Web Dashboard dependencies
npm install

# 2. Install Backend dependencies
cd backend
pip install -r requirements.txt
cd ..

# 3. Install Endpoint Agent dependencies
cd endpoint_agent
pip install -r requirements.txt
cd ..
```

---

## 2. How to Configure Firebase

The system comes pre-configured with Cloud Firestore integration:
- **Project ID**: `civil-acolyte-7xfhk`
- **Configuration File**: `src/firebase/config.ts` (and `firebase-applet-config.json`)
- **Security Rules**: Deployed in `firestore.rules`

### Firestore Collections:
- `users`: Security analysts and system operators
- `devices`: Monitored endpoints (e.g., `WINDOWS-PC-01`)
- `events`: File creation, modification, deletion, and rename telemetry
- `incidents`: Escalated security alerts with severity and recommended containment
- `protected_files`: Prioritized file inventory with SHA-256 integrity hashes
- `archives`: Immutable backup snapshots with cryptographic file manifests
- `audit_logs`: Audit trail for compliance and non-repudiation

*(Note: If running without internet connectivity, the web app automatically utilizes a persistent local storage cache, ensuring continuous operation).*

---

## 3. How to Start the Frontend

Start the Vite development dashboard server:

```bash
npm run dev
```

Open your browser and navigate to:
`http://localhost:3000`

---

## 4. How to Start the Backend

The FastAPI backend exposes the REST API required by endpoint agents and dashboards:

```bash
# From the project root
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI Swagger documentation will be accessible at:
`http://localhost:8000/docs`

Available REST endpoints:
- `POST /api/events` - Ingest raw file operations
- `GET /api/events` - Query event log
- `POST /api/incidents` - Record detected incidents
- `GET /api/incidents` - Query active/resolved incidents
- `GET /api/devices` - Query monitored endpoint statuses
- `GET /api/protected-files` - List prioritized files
- `POST /api/protected-files` - Add protected file
- `GET /api/archives` - Query archive manifests
- `POST /api/archives` - Generate new archive snapshot
- `POST /api/containment` - Issue containment or release command

---

## 5. How to Start the Windows Endpoint Agent

On the target Windows computer:

1. Edit `endpoint_agent/config.py` if you wish to adjust monitored paths (e.g. `C:\Users\<YourUser>\Documents`, `C:\ProtectedFiles`).
2. Run the agent:

```bash
cd endpoint_agent
python agent.py
```

The agent will attach Python `watchdog` hooks to the specified directories, monitoring for:
- File creations (`CREATE`)
- File modifications (`MODIFY`)
- File deletions (`DELETE`)
- File renames (`RENAME`)

---

## 6. How to Test the System Safely Using Harmless Test Files

> **SAFETY MANDATE**: This project uses rule-based heuristic detection and DOES NOT contain malicious code. Testing is conducted using benign `.txt` files in a dedicated temporary test directory.

### Method A: Using the Interactive Web Dashboard Simulation Lab (Instant)
1. In the Web Dashboard, click the **"Test / Simulate Lab"** button in the header.
2. Choose one of four test scenarios:
   - **Test 1: Normal Single File Modification** -> Risk remains 0–29 (Normal)
   - **Test 2: Rapid Burst of Modifications** -> Risk rises to 30–59 (Suspicious)
   - **Test 3: Tampering with Protected File (`database.sql`)** -> Risk rises to 60–79 (High)
   - **Test 4: Ransomware Encryption Simulation (`.locked` extension)** -> Risk reaches 80–100 (Critical), creates an incident (`INC-001`), and automatically triggers **Host Containment**.
3. Verify the incident in the **Incidents** tab, inspect the **Recent Security Events**, and click **[RELEASE DEVICE]** once reviewed.

### Method B: Using the Python Simulation Script on Windows
Run the provided benign testing script:

```bash
cd endpoint_agent
python test_ransomware_simulation.py
```

This creates a temporary `./test_sandbox` directory and allows you to test:
1. Isolated benign file edit.
2. Rapid multiple modifications.
3. Benign ransomware renaming simulation (appending `.locked` to harmless sample files).
4. Automatic clean-up and restoration.

---

## Future Raspberry Pi Integration

The architecture is prepared for a Raspberry Pi local server intermediary:
```
Windows Endpoint Agent → Raspberry Pi Local Server → Firebase
```
The Raspberry Pi can be enabled under **Settings** to act as an offline buffer storing:
- Local incident reports
- Security events queue
- Audit logs
- Protected file backup archives and manifests
