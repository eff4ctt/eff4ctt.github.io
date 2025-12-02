import time
import os
import sys
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RebuildHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_build = 0
        self.cooldown = 1 # Seconds between builds

    def on_any_event(self, event):
        if event.is_directory:
            return
        
        # Only watch relevant files
        if not (event.src_path.endswith('.md') or 
                event.src_path.endswith('.css') or 
                event.src_path.endswith('.html') or
                event.src_path.endswith('.py')):
            return

        # Avoid build loops (ignore docs/)
        if "docs/" in event.src_path:
            return

        current_time = time.time()
        if current_time - self.last_build > self.cooldown:
            print(f"Detected change in {event.src_path}. Rebuilding...")
            subprocess.run([sys.executable, "build.py"])
            self.last_build = current_time

if __name__ == "__main__":
    # Check if watchdog is installed
    try:
        import watchdog
    except ImportError:
        print("Installing watchdog library for auto-rebuild...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "watchdog"])
        print("Done. Starting watcher...")

    path = "."
    event_handler = RebuildHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    print(f"Watching for changes in {os.getcwd()}...")
    print("Press Ctrl+C to stop.")
    
    # Run one initial build
    subprocess.run([sys.executable, "build.py"])

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
