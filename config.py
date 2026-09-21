"""
Endpoint Agent Configuration
----------------------------
Handles configuration for the Windows Python Endpoint Watchdog Agent,
including monitored directory selection, safety validations, device identity,
and backend API connection settings.
"""

import os
import sys
import socket
import platform
from typing import List, Dict, Any

# Default safe directories to monitor on Windows.
# WARNING: NEVER monitor the entire root drive (e.g. C:\) because system processes,
# pagefiles, and logs generate thousands of events per second and will degrade performance.
DEFAULT_MONITORED_DIRS: List[str] = [
    os.path.expanduser(r"~\Documents"),
    os.path.expanduser(r"~\Desktop"),
    os.path.expanduser(r"~\TestFolder"),
]

# Behavioral Detection Engine Heuristic Constants
TIME_WINDOW_SECONDS: int = 10
SUSPICIOUS_EXTENSIONS: List[str] = [
    ".locked", ".crypto", ".enc", ".crypted", ".ransom",
    ".wnry", ".crypt", ".locky", ".darkness", ".payme"
]
PROTECTED_FILENAMES: List[str] = [
    "database.sql", "project.zip", "report.docx",
    "payroll_master.csv", "budget_2026.xlsx", "customer_records.db"
]

# FastAPI backend API URL
DEFAULT_BACKEND_API_URL: str = os.environ.get("BACKEND_API_URL", "http://localhost:8000/api")

# Device Identity detection
def get_device_hostname() -> str:
    """Retrieve machine hostname."""
    try:
        return socket.gethostname() or "WINDOWS-PC-01"
    except Exception:
        return "WINDOWS-PC-01"

def get_device_ip() -> str:
    """Retrieve local IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_os_info() -> str:
    """Retrieve OS platform string."""
    try:
        return f"{platform.system()} {platform.release()} ({platform.machine()})"
    except Exception:
        return "Windows 11"

def is_root_drive(path: str) -> bool:
    """
    Checks if a given path targets an entire root drive or filesystem root.
    Examples that return True: 'C:', 'C:\\', 'C:/', 'D:\\', '/', '\\'
    """
    normalized = os.path.abspath(path).strip()
    drive, tail = os.path.splitdrive(normalized)
    
    # Windows drive root check: 'C:\' or 'C:/'
    if drive and tail in ["\\", "/", ""]:
        return True
    
    # Unix root check
    if normalized in ["/", "\\"]:
        return True
    
    return False

def validate_and_resolve_directories(dirs: List[str]) -> List[str]:
    """
    Validates user-selected directories.
    - Resolves user home paths (~).
    - Prohibits monitoring entire root drives (C:\\).
    - Ensures directories exist or creates them safely.
    """
    valid_dirs: List[str] = []
    
    for d in dirs:
        if not d or not d.strip():
            continue
            
        expanded = os.path.expanduser(d.strip())
        resolved = os.path.abspath(expanded)
        
        # Guard: Do not monitor entire C:\ drive
        if is_root_drive(resolved):
            print(f"[!] SAFETY WARNING: Cannot monitor root drive '{resolved}'.")
            print("    Monitoring the entire C:\\ drive degrades system performance and floods logs.")
            print("    Please select a specific subfolder such as C:\\Users\\...\\Documents or C:\\TestFolder.")
            continue
            
        # Ensure the directory exists
        try:
            if not os.path.exists(resolved):
                os.makedirs(resolved, exist_ok=True)
                print(f"[*] Created monitored directory: {resolved}")
            valid_dirs.append(resolved)
        except Exception as err:
            print(f"[-] Could not access or create directory '{resolved}': {err}")

    # Fallback to local test sandbox if all paths were invalid
    if not valid_dirs:
        fallback = os.path.abspath("./monitored_test_dir")
        os.makedirs(fallback, exist_ok=True)
        print(f"[!] No valid folders specified. Using fallback test folder: {fallback}")
        valid_dirs.append(fallback)

    return list(dict.fromkeys(valid_dirs))  # Deduplicate while preserving order

def get_agent_config(
    custom_dirs: List[str] = None,
    backend_url: str = None
) -> Dict[str, Any]:
    """
    Builds the active configuration dictionary from CLI arguments,
    environment variables, or defaults.
    """
    # 1. Determine directories: CLI arg > Environment Variable > Defaults
    if custom_dirs:
        raw_dirs = custom_dirs
    elif "MONITORED_DIRS" in os.environ:
        # Support comma or semicolon delimited list
        raw_dirs = [p.strip() for p in os.environ["MONITORED_DIRS"].replace(";", ",").split(",") if p.strip()]
    else:
        raw_dirs = DEFAULT_MONITORED_DIRS

    resolved_dirs = validate_and_resolve_directories(raw_dirs)

    # 2. Determine backend API URL
    api_url = backend_url or os.environ.get("BACKEND_API_URL", DEFAULT_BACKEND_API_URL)
    api_url = api_url.rstrip("/")

    return {
        "monitored_directories": resolved_dirs,
        "backend_api_url": api_url,
        "device_hostname": get_device_hostname(),
        "device_ip": get_device_ip(),
        "device_os": get_os_info()
    }
