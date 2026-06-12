#!/usr/bin/env python3
"""
Agnivarta AI - One-click startup script
Launches the FastAPI backend server and opens the frontend.
"""
import os
import sys
import subprocess
import time
import webbrowser
import socket

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def main():
    print("=" * 60)
    print("  AGNIVARTA AI  -  Intelligent Fire Network")
    print("  NovaBank Security Platform v1.0")
    print("=" * 60)

    # Install dependencies if needed
    print("\n[1/3] Checking dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install",
                    "fastapi", "uvicorn", "pydantic", "--break-system-packages", "-q"],
                   check=False)
    print("      Dependencies ready.")

    # Ensure directories exist
    os.makedirs("database", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    # Start backend
    print("\n[2/3] Starting Agnivarta AI backend (port 8000)...")
    if check_port(8000):
        print("      Port 8000 already in use - assuming server is running.")
    else:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.main:app",
             "--host", "127.0.0.1", "--port", "8000"],
            stdout=open("logs/server.log","w"),
            stderr=subprocess.STDOUT
        )
        # Wait for startup
        for i in range(12):
            time.sleep(1)
            if check_port(8000):
                print("      Backend running: http://127.0.0.1:8000")
                break
            print(f"      Waiting... ({i+1}s)")
        else:
            print("      ERROR: Backend failed to start. Check logs/server.log")
            sys.exit(1)

    # Open frontend
    print("\n[3/3] Opening NovaBank + Agnivarta AI frontend...")
    frontend_path = os.path.abspath("frontend/index.html")
    if os.path.exists(frontend_path):
        webbrowser.open("file://" + frontend_path)
        print(f"      Frontend opened: {frontend_path}")
    else:
        print(f"      Frontend not found at {frontend_path}")

    print("\n" + "=" * 60)
    print("  SYSTEM READY")
    print()
    print("  Frontend:  file://frontend/index.html")
    print("  API:       http://127.0.0.1:8000")
    print("  API Docs:  http://127.0.0.1:8000/docs")
    print()
    print("  Demo logins:")
    print("    arjun@novabank.com / user1pass   (Trusted user)")
    print("    vikram@novabank.com / user5pass  (High-risk user)")
    print("    admin@novabank.com / adminpass   (Admin)")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down Agnivarta AI. Goodbye.")

if __name__ == "__main__":
    main()
