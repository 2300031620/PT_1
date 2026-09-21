"""
File System Monitor
-------------------
Uses Python watchdog to monitor user-configured directories and capture
real-time file system events:
  - CREATE
  - MODIFY
  - DELETE
  - MOVE/RENAME

Does not perform ransomware analysis; solely captures and forwards file events.
"""

import os
import time
from typing import Callable, List
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent
)

# Callback type signature:
# on_event(event_type: str, file_path: str, old_path: str = None, details: str = "")
EventCallback = Callable[[str, str, str, str], None]

class EndpointFileEventHandler(FileSystemEventHandler):
    """
    Watches for file modifications, creations, deletions, and moves/renames.
    Filters out pure directory changes so that downstream consumers receive
    precise file-level operations.
    """

    def __init__(self, callback: EventCallback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        # Ignore directory creations, monitor file events only
        if event.is_directory:
            return
        file_path = os.path.normpath(event.src_path)
        filename = os.path.basename(file_path)
        self.callback("CREATE", file_path, None, f"File created: {filename}")

    def on_modified(self, event):
        # Ignore directory metadata modifications
        if event.is_directory:
            return
        file_path = os.path.normpath(event.src_path)
        filename = os.path.basename(file_path)
        self.callback("MODIFY", file_path, None, f"File content or attributes modified: {filename}")

    def on_deleted(self, event):
        # Ignore directory deletions
        if event.is_directory:
            return
        file_path = os.path.normpath(event.src_path)
        filename = os.path.basename(file_path)
        self.callback("DELETE", file_path, None, f"File deleted: {filename}")

    def on_moved(self, event):
        # Ignore directory renames
        if event.is_directory:
            return
        src_path = os.path.normpath(event.src_path)
        dest_path = os.path.normpath(event.dest_path)
        old_name = os.path.basename(src_path)
        new_name = os.path.basename(dest_path)
        self.callback("MOVE/RENAME", dest_path, src_path, f"File moved/renamed: {old_name} -> {new_name}")


class EndpointFileMonitor:
    """
    Manages the watchdog Observer across one or multiple user-configured directories.
    """

    def __init__(self, directories: List[str], event_callback: EventCallback):
        self.directories = directories
        self.event_callback = event_callback
        self.observer = Observer()
        self.handler = EndpointFileEventHandler(self.event_callback)
        self._is_running = False

    def start(self):
        """
        Schedules watches on all configured directories and starts the watchdog observer thread.
        """
        if self._is_running:
            return

        scheduled_count = 0
        for folder in self.directories:
            folder_path = os.path.abspath(folder)
            if not os.path.exists(folder_path):
                try:
                    os.makedirs(folder_path, exist_ok=True)
                except Exception as err:
                    print(f"[-] Failed to create monitored path {folder_path}: {err}")
                    continue

            try:
                # Schedule recursive file observation
                self.observer.schedule(self.handler, path=folder_path, recursive=True)
                scheduled_count += 1
                print(f"[+] Actively monitoring: {folder_path}")
            except Exception as err:
                print(f"[-] Could not schedule monitor on {folder_path}: {err}")

        if scheduled_count == 0:
            raise RuntimeError("No valid directories could be scheduled for monitoring.")

        self.observer.start()
        self._is_running = True
        print(f"[*] Watchdog observer started. Monitoring {scheduled_count} directory trees.")

    def stop(self):
        """
        Stops the observer and waits for the thread to join.
        """
        if self._is_running and self.observer.is_alive():
            print("[*] Stopping file system observer...")
            self.observer.stop()
            self.observer.join(timeout=5)
            self._is_running = False
            print("[*] File system observer cleanly stopped.")

    def is_alive(self) -> bool:
        return self._is_running and self.observer.is_alive()
