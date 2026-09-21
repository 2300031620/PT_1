#!/usr/bin/env python3
"""
Academic Harmless Ransomware Simulation Test Script
---------------------------------------------------
SAFETY NOTICE:
This script operates ONLY on harmless dummy text files created in a
dedicated test folder. It NEVER executes malicious code, NEVER touches
system files, and DOES NOT perform irreversible encryption.
"""

import os
import time
import sys

# Default to a sandbox directory in current directory or user documents
SANDBOX_DIR = os.path.abspath("./test_sandbox")

def setup_sandbox():
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    # Remove any stale leftovers from prior test runs
    for item in os.listdir(SANDBOX_DIR):
        item_path = os.path.join(SANDBOX_DIR, item)
        if os.path.isfile(item_path):
            try:
                os.remove(item_path)
            except Exception:
                pass

    print(f"[*] Initialized isolated testing sandbox at:\n    {SANDBOX_DIR}")

    # Create harmless mock files
    for i in range(1, 8):
        file_path = os.path.join(SANDBOX_DIR, f"sample_doc_{i}.txt")
        with open(file_path, "w") as f:
            f.write(f"This is an academic test document {i} for benign ransomware detection testing.\n")
    print("[*] Created 7 benign test files.")

def test_normal_activity():
    print("\n--- TEST 1: Simulating Normal Single File Modification (Low Risk) ---")
    test_file = os.path.join(SANDBOX_DIR, "sample_doc_1.txt")
    if not os.path.exists(test_file):
        with open(test_file, "w") as f:
            f.write("Initial test content\n")
    with open(test_file, "a") as f:
        f.write(f"\nUser edit at {time.strftime('%X')}")
    print(f"[+] Modified {test_file}. Expected Result: Normal / Low Risk (0-29).")
    time.sleep(1)

def test_rapid_modifications():
    print("\n--- TEST 2: Simulating Rapid File Modifications (Suspicious/High Risk) ---")
    for i in range(1, 6):
        test_file = os.path.join(SANDBOX_DIR, f"sample_doc_{i}.txt")
        if not os.path.exists(test_file):
            with open(test_file, "w") as f:
                f.write(f"Sample test document {i}\n")
        with open(test_file, "a") as f:
            f.write(f"\nRapid edit iteration {time.time()}")
        print(f"    Modified sample_doc_{i}.txt")
        time.sleep(0.05)
    print("[+] Performed 5 modifications in <1s. Expected Result: Suspicious/High Risk (30-65).")
    time.sleep(1)

def test_ransomware_renaming_simulation():
    print("\n--- TEST 3: Simulating Ransomware Renaming (.locked extension) ---")
    print("[!] Notice: Only renaming benign test files created in step 1.")
    renamed = []
    for i in range(1, 6):
        old_path = os.path.join(SANDBOX_DIR, f"sample_doc_{i}.txt")
        new_path = os.path.join(SANDBOX_DIR, f"sample_doc_{i}.txt.locked")
        if os.path.exists(old_path):
            os.rename(old_path, new_path)
            renamed.append(new_path)
            print(f"    Renamed {os.path.basename(old_path)} -> {os.path.basename(new_path)}")
        time.sleep(0.15)
    print("\n[!] Expected Result: CRITICAL Risk (80-100) -> Containment Triggered!")
    time.sleep(3)

def cleanup_sandbox():
    print("\n--- CLEANUP: Restoring/Removing Sandbox ---")
    if os.path.exists(SANDBOX_DIR):
        for root, dirs, files in os.walk(SANDBOX_DIR, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(SANDBOX_DIR)
        print("[*] Test sandbox cleaned up safely.")

def main():
    print("=================================================================")
    print("  SAFE RANSOMWARE HEURISTICS SIMULATION SUITE (ACADEMIC USE)     ")
    print("=================================================================")
    setup_sandbox()

    print("\nSelect an action:")
    print("1) Run Test 1: Normal Single File Modification")
    print("2) Run Test 2: Rapid Multiple Modifications")
    print("3) Run Test 3: Ransomware Simulation (.locked extensions)")
    print("4) Run All Tests Sequentially")
    print("5) Cleanup Sandbox")
    print("6) Exit")

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--auto", "--all", "-a", "4"]:
            choice = "4"
        elif arg in ["1", "--normal"]:
            choice = "1"
        elif arg in ["2", "--rapid"]:
            choice = "2"
        elif arg in ["3", "--ransomware"]:
            choice = "3"
        elif arg in ["5", "--clean"]:
            choice = "5"
        else:
            choice = "4"
        cleanup_auto = True
    elif not sys.stdin.isatty():
        choice = "4"
        cleanup_auto = True
    else:
        choice = input("\nEnter choice (1-6) [default: 4]: ").strip() or "4"
        cleanup_auto = False

    if choice == "1":
        test_normal_activity()
    elif choice == "2":
        test_rapid_modifications()
    elif choice == "3":
        test_ransomware_renaming_simulation()
    elif choice == "4":
        test_normal_activity()
        time.sleep(2)
        test_rapid_modifications()
        time.sleep(2)
        test_ransomware_renaming_simulation()
    elif choice == "5":
        cleanup_sandbox()
        return
    else:
        return

    if cleanup_auto:
        cleanup_choice = "y"
    else:
        cleanup_choice = input("\nClean up test sandbox now? (y/n) [default: y]: ").strip().lower() or "y"
    if cleanup_choice == "y":
        cleanup_sandbox()

if __name__ == "__main__":
    main()
