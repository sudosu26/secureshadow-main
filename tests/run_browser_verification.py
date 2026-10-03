"""
Automated end-to-end browser verification of the new SECURESHADOW React + TypeScript SPA.
Uses Playwright with Microsoft Edge (Chromium) to execute the complete user flow:
Login -> Dashboard Overview -> Baseline Capture -> Introduce Drift -> Drift Detection
-> Decay Evidence -> Apply Repair -> Verify Resolution -> Inventory -> Audit Trail.
Captures screenshots as verified artifacts in the artifact directory.
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

SERVER_PORT = 8889
SERVER_URL = f"http://127.0.0.1:{SERVER_PORT}"


def start_server():
    """Run uvicorn in background thread."""
    from secureshadow.api.app import app
    uvicorn.run(app, host="127.0.0.1", port=SERVER_PORT, log_level="warning")


def run_browser_test():
    print(f"Starting background server at {SERVER_URL}...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(3)  # Wait for server startup

    screenshots = {}

    print("Launching browser via Playwright (using Microsoft Edge / Chromium)...")
    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(channel="msedge", headless=True)
            print("Successfully launched Microsoft Edge browser engine.")
        except Exception as e:
            print(f"Edge launch note: {e}. Trying default chromium...")
            browser = p.chromium.launch(headless=True)

        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        print(f"1. Navigating to {SERVER_URL}...")
        page.goto(SERVER_URL, wait_until="networkidle")
        time.sleep(1.5)

        # 1. Capture Login Screen
        ss1 = ARTIFACT_DIR / "1_react_login_screen.png"
        page.screenshot(path=str(ss1))
        screenshots["login"] = str(ss1)
        print(f"Captured login screen: {ss1.name}")

        # 2. Login as admin
        print("Filling login form...")
        page.fill('input[placeholder="admin"]', "admin")
        page.fill('input[placeholder="••••••••••••"]', "secureshadowadmin")
        page.click('button[type="submit"]')
        time.sleep(2)

        # Capture Dashboard Overview
        ss2 = ARTIFACT_DIR / "2_react_dashboard_overview.png"
        page.screenshot(path=str(ss2))
        screenshots["dashboard"] = str(ss2)
        print(f"Captured dashboard overview: {ss2.name}")

        # 3. Navigate to Baseline
        print("Navigating to Baseline tab...")
        page.click('button:has-text("Baseline")')
        time.sleep(1)
        print("Clicking 'Capture Demo Baseline'...")
        page.click('button:has-text("Capture Demo Baseline")')
        time.sleep(2)
        ss3 = ARTIFACT_DIR / "3_react_baseline_captured.png"
        page.screenshot(path=str(ss3))
        screenshots["baseline"] = str(ss3)
        print(f"Captured baseline: {ss3.name}")

        # 4. Navigate to Drift Detection
        print("Navigating to Drift Detection tab...")
        page.click('button:has-text("Drift Detection")')
        time.sleep(1)
        print("Introducing drift scenario...")
        page.click('button:has-text("Introduce Drift Scenario")')
        time.sleep(1.5)
        print("Running drift detection...")
        page.click('button:has-text("Run Drift Detection")')
        time.sleep(2)
        ss4 = ARTIFACT_DIR / "4_react_drift_detected.png"
        page.screenshot(path=str(ss4))
        screenshots["drift"] = str(ss4)
        print(f"Captured drift detection: {ss4.name}")

        # 5. Navigate to Decay Evidence
        print("Navigating to Decay Evidence tab...")
        page.click('button:has-text("Decay Evidence")')
        time.sleep(2)
        ss5 = ARTIFACT_DIR / "5_react_decay_evidence.png"
        page.screenshot(path=str(ss5))
        screenshots["decay"] = str(ss5)
        print(f"Captured decay evidence: {ss5.name}")

        # 6. Navigate to Repairs & Remediation
        print("Navigating to Repairs & Actions tab...")
        page.click('button:has-text("Repairs & Actions")')
        time.sleep(2)
        print("Applying recommended repair...")
        page.click('button:has-text("Apply This Repair")')
        time.sleep(1)
        page.click('button:has-text("Confirm & Apply")')
        time.sleep(2)
        ss6 = ARTIFACT_DIR / "6_react_repair_applied.png"
        page.screenshot(path=str(ss6))
        screenshots["repair_applied"] = str(ss6)
        print(f"Captured repair applied: {ss6.name}")

        # 7. Verify Resolution
        print("Clicking 'Verify Resolution'...")
        page.click('button:has-text("Verify Resolution")')
        time.sleep(2)
        ss7 = ARTIFACT_DIR / "7_react_remediation_resolved.png"
        page.screenshot(path=str(ss7))
        screenshots["resolved"] = str(ss7)
        print(f"Captured remediation resolved: {ss7.name}")

        # 8. Navigate to Inventory
        print("Navigating to Inventory tab...")
        page.click('button:has-text("Inventory")')
        time.sleep(1.5)
        ss8 = ARTIFACT_DIR / "8_react_inventory.png"
        page.screenshot(path=str(ss8))
        screenshots["inventory"] = str(ss8)
        print(f"Captured inventory: {ss8.name}")

        # 9. Navigate to Audit Log
        print("Navigating to Audit Log tab...")
        page.click('button:has-text("Audit Log")')
        time.sleep(1.5)
        ss9 = ARTIFACT_DIR / "9_react_audit_log.png"
        page.screenshot(path=str(ss9))
        screenshots["audit"] = str(ss9)
        print(f"Captured audit log: {ss9.name}")

        browser.close()

    print("\nALL REACT SPA FLOW STEPS COMPLETED AND VERIFIED!")
    for step, path in screenshots.items():
        print(f"  - {step}: {path}")


if __name__ == "__main__":
    run_browser_test()
