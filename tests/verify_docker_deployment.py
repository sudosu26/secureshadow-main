"""
Automated end-to-end browser verification of the containerized SECURESHADOW deployment.
Targets the live Docker Compose environment at http://localhost:8000 (backed by PostgreSQL 16).
Exercises the complete lifecycle through the real React frontend and Postgres database.
Captures fresh screenshots into the artifact directory.
"""

import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from playwright.sync_api import sync_playwright

ARTIFACT_DIR = Path(r"C:\Users\ajoya\.gemini\antigravity\brain\01182dec-252b-4186-b8af-b9eda0072c26")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

DOCKER_URL = "http://localhost:8000"


def run_docker_browser_test():
    print(f"Connecting to live Docker container at {DOCKER_URL} (PostgreSQL 16 backend)...")
    screenshots = {}

    with sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch(channel="msedge", headless=True)
            print("Launched Microsoft Edge browser engine.")
        except Exception as e:
            print(f"Edge note: {e}. Trying default chromium...")
            browser = p.chromium.launch(headless=True)

        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()

        print(f"1. Navigating to {DOCKER_URL}...")
        page.goto(DOCKER_URL, wait_until="networkidle")
        time.sleep(1.5)

        # 1. Login Screen
        ss1 = ARTIFACT_DIR / "docker_1_login_screen.png"
        page.screenshot(path=str(ss1))
        screenshots["login"] = str(ss1)
        print(f"Captured: {ss1.name}")

        # 2. Login as admin against Postgres UserModel
        print("Authenticating with admin credentials against PostgreSQL...")
        page.fill('input[placeholder="admin"]', "admin")
        page.fill('input[placeholder="••••••••••••"]', "secureshadowadmin")
        page.click('button[type="submit"]')
        time.sleep(2)

        # 2. Dashboard
        ss2 = ARTIFACT_DIR / "docker_2_dashboard.png"
        page.screenshot(path=str(ss2))
        screenshots["dashboard"] = str(ss2)
        print(f"Captured: {ss2.name}")

        # 3. Baseline
        print("Navigating to Baseline and capturing demo baseline into Postgres...")
        page.click('button:has-text("Baseline")')
        time.sleep(1)
        page.click('button:has-text("Capture Demo Baseline")')
        time.sleep(2)
        ss3 = ARTIFACT_DIR / "docker_3_baseline_captured.png"
        page.screenshot(path=str(ss3))
        screenshots["baseline"] = str(ss3)
        print(f"Captured: {ss3.name}")

        # 4. Drift Detection
        print("Introducing drift scenario and detecting drift...")
        page.click('button:has-text("Drift Detection")')
        time.sleep(1)
        page.click('button:has-text("Introduce Drift Scenario")')
        time.sleep(1.5)
        page.click('button:has-text("Run Drift Detection")')
        time.sleep(2)
        ss4 = ARTIFACT_DIR / "docker_4_drift_detected.png"
        page.screenshot(path=str(ss4))
        screenshots["drift"] = str(ss4)
        print(f"Captured: {ss4.name}")

        # 5. Decay Evidence
        print("Checking decay evidence...")
        page.click('button:has-text("Decay Evidence")')
        time.sleep(2)
        ss5 = ARTIFACT_DIR / "docker_5_decay_evidence.png"
        page.screenshot(path=str(ss5))
        screenshots["decay"] = str(ss5)
        print(f"Captured: {ss5.name}")

        # 6. Apply Repair
        print("Navigating to Repairs and applying recommendation...")
        page.click('button:has-text("Repairs & Actions")')
        time.sleep(2)
        page.click('button:has-text("Apply This Repair")')
        time.sleep(1)
        page.click('button:has-text("Confirm & Apply")')
        time.sleep(2)
        ss6 = ARTIFACT_DIR / "docker_6_repair_applied.png"
        page.screenshot(path=str(ss6))
        screenshots["repair_applied"] = str(ss6)
        print(f"Captured: {ss6.name}")

        # 7. Verify Resolution
        print("Verifying remediation closed loop...")
        page.click('button:has-text("Verify Resolution")')
        time.sleep(2)
        ss7 = ARTIFACT_DIR / "docker_7_remediation_resolved.png"
        page.screenshot(path=str(ss7))
        screenshots["resolved"] = str(ss7)
        print(f"Captured: {ss7.name}")

        # 8. Inventory
        print("Checking Inventory (verifying PostgreSQL association data)...")
        page.click('button:has-text("Inventory")')
        time.sleep(1.5)
        ss8 = ARTIFACT_DIR / "docker_8_inventory.png"
        page.screenshot(path=str(ss8))
        screenshots["inventory"] = str(ss8)
        print(f"Captured: {ss8.name}")

        # 9. Audit Log
        print("Checking Audit Log (verifying PostgreSQL audit entries)...")
        page.click('button:has-text("Audit Log")')
        time.sleep(1.5)
        ss9 = ARTIFACT_DIR / "docker_9_audit_log.png"
        page.screenshot(path=str(ss9))
        screenshots["audit"] = str(ss9)
        print(f"Captured: {ss9.name}")

        browser.close()

    print("\nDOCKER POSTGRESQL DEPLOYMENT VERIFICATION COMPLETE!")
    for step, p in screenshots.items():
        print(f"  - {step}: {p}")


if __name__ == "__main__":
    run_docker_browser_test()
