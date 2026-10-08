#!/usr/bin/env python3
"""Start the SECURESHADOW toolchain with one command."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8000


def find_python() -> str:
    candidates = [
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
        Path(sys.executable),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def ensure_environment(python: str) -> None:
    dependency_check = subprocess.run(
        [
            python,
            "-c",
            "import alembic, apscheduler, bcrypt, fastapi, jwt, networkx, pydantic, "
            "slowapi, sqlalchemy, uvicorn",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if dependency_check.returncode == 0:
        return

    print("[SECURESHADOW] Required dependencies are missing; installing the project environment.")
    installation = subprocess.run(
        [python, "-m", "pip", "install", "--disable-pip-version-check", "-e", str(ROOT)],
        cwd=str(ROOT),
        check=False,
    )
    if installation.returncode:
        raise RuntimeError(
            f"Dependency installation failed with exit code {installation.returncode}."
        )


def wait_for_api(url: str, process: subprocess.Popen, timeout_seconds: int = 45) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    last_error = "No health-check response received."
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            return False, f"Server process exited during startup with code {exit_code}."
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True, ""
        except OSError as error:
            last_error = str(error)
            time.sleep(0.5)
    return False, f"Health check timed out after {timeout_seconds}s: {last_error}"


def run_demo(python: str) -> None:
    print("\n[SECURESHADOW] Running the canonical demo scenario...\n")
    subprocess.run(
        [python, str(ROOT / "secureshadow" / "cli.py"), "demo"],
        cwd=str(ROOT),
        check=True,
    )


def start_server(python: str, host: str, port: int, open_browser: bool) -> int:
    url = f"http://{host}:{port}"
    print(f"\n[SECURESHADOW] Starting API server at {url}\n")

    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")

    proc = subprocess.Popen(
        [python, "-m", "uvicorn", "secureshadow.api.app:app", "--host", host, "--port", str(port)],
        cwd=str(ROOT),
        env=env,
    )

    try:
        ready, error = wait_for_api(f"{url}/health", proc)
        if not ready:
            print(f"\n[SECURESHADOW] Server failed to start: {error}")
            return proc.poll() or 1

        print(f"[SECURESHADOW] Server is ready. Open: {url}")
        if open_browser:
            webbrowser.open(url)

        proc.wait()
        return proc.returncode or 0
    except KeyboardInterrupt:
        print("\n[SECURESHADOW] Shutting down server...")
        return 130
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch the SECURESHADOW security monitoring tool.")
    parser.add_argument("--host", default=HOST, help="Host interface to bind the API server to.")
    parser.add_argument("--port", type=int, default=PORT, help="Port for the FastAPI server.")
    parser.add_argument("--demo", action="store_true", help="Run the canonical CLI demo before starting the server.")
    parser.add_argument("--no-browser", action="store_true", help="Do not attempt to open the browser automatically.")
    parser.add_argument("--no-server", action="store_true", help="Skip starting the API server and only run the demo if requested.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    python = find_python()
    try:
        ensure_environment(python)
    except RuntimeError as error:
        print(f"[SECURESHADOW] {error}", file=sys.stderr)
        return 1

    if args.demo:
        try:
            run_demo(python)
        except subprocess.CalledProcessError as error:
            return error.returncode

    if args.no_server:
        return 0

    return start_server(python, args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    raise SystemExit(main())
