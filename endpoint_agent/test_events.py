"""
Endpoint Agent File System Test Script
--------------------------------------
A safe verification tool that generates the 4 core file operations in an isolated
monitored test directory so you can verify watchdog detection and backend event streaming:
  1. CREATE: Creates 'audit_sample.txt'
  2. MODIFY: Appends new content to 'audit_sample.txt'
  3. MOVE/RENAME: Renames 'audit_sample.txt' -> 'archived_sample.txt'
  4. DELETE: Deletes 'archived_sample.txt'

SAFETY: Operates strictly within the specified test directory.
"""

import os
import sys
import time
import argparse

def run_test(test_directory: str, prompt: bool = True):
    abs_dir = os.path.abspath(test_directory)
    os.makedirs(abs_dir, exist_ok=True)

    print("=" * 65)
    print("      WATCHDOG FILE EVENT GENERATOR / VERIFICATION TEST")
    print("=" * 65)
    print(f"Target Directory: {abs_dir}")
    print("Make sure the Endpoint Agent is running and monitoring this path!")
    print("=" * 65)

    if prompt and sys.stdin.isatty():
        input("\nPress Enter to begin test sequence...")
    else:
        print("\nStarting test sequence automatically...")

    test_file_path = os.path.join(abs_dir, "audit_sample.txt")
    renamed_file_path = os.path.join(abs_dir, "archived_sample.txt")

    # Step 1: CREATE
    print("\n[Step 1/4] Triggering CREATE event...")
    with open(test_file_path, "w", encoding="utf-8") as f:
        f.write("Initial document content for academic watchdog testing.\n")
    print(f"  --> Created file: {test_file_path}")
    print("  --> Watchdog agent should display: [+] CREATE")
    time.sleep(2)

    # Step 2: MODIFY
    print("\n[Step 2/4] Triggering MODIFY event...")
    with open(test_file_path, "a", encoding="utf-8") as f:
        f.write(f"Appended test line at timestamp: {time.time()}\n")
    print(f"  --> Modified file: {test_file_path}")
    print("  --> Watchdog agent should display: [*] MODIFY")
    time.sleep(2)

    # Step 3: MOVE/RENAME
    print("\n[Step 3/4] Triggering MOVE/RENAME event...")
    if os.path.exists(renamed_file_path):
        os.remove(renamed_file_path)
    os.rename(test_file_path, renamed_file_path)
    print(f"  --> Renamed: audit_sample.txt -> archived_sample.txt")
    print("  --> Watchdog agent should display: [>] MOVE/RENAME")
    time.sleep(2)

    # Step 4: DELETE
    print("\n[Step 4/4] Triggering DELETE event...")
    if os.path.exists(renamed_file_path):
        os.remove(renamed_file_path)
    print(f"  --> Deleted file: {renamed_file_path}")
    print("  --> Watchdog agent should display: [-] DELETE")
    time.sleep(1)

    print("\n" + "=" * 65)
    print("  TEST COMPLETE: All 4 events (CREATE, MODIFY, MOVE/RENAME, DELETE)")
    print("  were generated. Check your Agent terminal and FastAPI dashboard!")
    print("=" * 65)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test file operations for Endpoint Agent")
    parser.add_argument(
        "--dir", "-d",
        type=str,
        default="./monitored_test_dir",
        help="Path to the monitored directory where test files will be created"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip prompt and start immediately"
    )
    args = parser.parse_args()
    run_test(args.dir, prompt=not args.yes)
