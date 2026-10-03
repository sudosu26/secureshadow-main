"""
Verification script for Track C:
1. Baseline Distinction (Production vs Sample Demo)
2. Password Rotation Modal
3. 404 Route Not Found View
"""

import sys
import time
import threading
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import uvicorn
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = Path(r"C:\Users\ajoya\.gemini\antigravity\brain\01182dec-252b-4186-b8af-b9eda0072c26")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

SERVER_PORT = 8891
SERVER_URL = f"http://127.0.0.1:{SERVER_PORT}"


def start_server():
    from secureshadow.api.app import app
    uvicorn.run(app, host="127.0.0.1", port=SERVER_PORT, log_level="warning")


def run_track_c_test():
    print(f"Starting server at {SERVER_URL}...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(3)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="msedge", headless=True)
        except Exception:
            browser = p.chromium.launch(headless=True)

        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        # 1. Login
        page.goto(SERVER_URL, wait_until="networkidle")
        time.sleep(1)
        page.fill('input[placeholder="admin"]', "admin")
        page.fill('input[placeholder="••••••••••••"]', "secureshadowadmin")
        page.click('button[type="submit"]')
        time.sleep(2)

        # 2. Track C.1: Baseline View Distinction
        print("Navigating to Baseline View to verify visual separation...")
        page.click('button:has-text("Baseline")')
        time.sleep(1.5)
        ss1 = ARTIFACT_DIR / "track_c_1_baseline_distinction.png"
        page.screenshot(path=str(ss1))
        print(f"Captured: {ss1.name} (Title: {page.title()})")

        # 3. Track C.2: Change Password Modal
        print("Opening Password Rotation Modal...")
        page.click('button[title="Rotate Admin Password"]')
        time.sleep(1)
        ss2 = ARTIFACT_DIR / "track_c_2_change_password_modal.png"
        page.screenshot(path=str(ss2))
        print(f"Captured: {ss2.name}")

        # Close modal
        page.click('button:has-text("Cancel")')
        time.sleep(0.5)

        # 4. Track C.3: 404 Route Not Found
        print("Navigating to unknown route /invalid-audit-link to verify 404 state...")
        page.goto(f"{SERVER_URL}/invalid-audit-link", wait_until="networkidle")
        time.sleep(1.5)
        ss3 = ARTIFACT_DIR / "track_c_3_404_not_found.png"
        page.screenshot(path=str(ss3))
        print(f"Captured: {ss3.name} (Title: {page.title()})")

        browser.close()

    print("\nTRACK C VERIFICATION COMPLETE!")


if __name__ == "__main__":
    run_track_c_test()
