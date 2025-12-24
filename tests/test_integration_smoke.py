import os
import socket
import subprocess  # nosec: B404 - used intentionally in integration tests
import sys
import time


def wait_for_port(host: str, port: int, timeout: int = 10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {host}:{port}")


def test_end_to_end_smoke():
    # Start the vulnerable server
    server_proc = subprocess.Popen(  # nosec: B603 - invoked with fixed args in controlled test
        [sys.executable, "vulnerable_server.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        wait_for_port("127.0.0.1", 8080, timeout=15)
        print("[TEST] Server is ready")

        outname = "ci_smoke_test"
        cmd = [
            sys.executable,
            "vscanx.py",
            "-t",
            "http://127.0.0.1:8080/search?q=test",
            "-s",
            "web",
            "--skip-warning",
            "--format",
            "html,json,csv,txt",
            "-o",
            outname,
        ]

        print("[TEST] Running VScanX CLI...")
        res = subprocess.run(cmd, timeout=120, capture_output=True, text=True)  # nosec: B603 - invoked with fixed args in controlled test

        if res.returncode != 0:
            print(f"[TEST] CLI stdout:\n{res.stdout}")
            print(f"[TEST] CLI stderr:\n{res.stderr}")
        assert res.returncode == 0, f"vscanx failed with exit code {res.returncode}"  # nosec: B101 - test assertion

        # Verify reports
        print("[TEST] Verifying reports...")
        base_dir = os.path.abspath("reports")
        for ext in ("html", "json", "csv", "txt"):
            path = os.path.join(base_dir, f"{outname}.{ext}")
            assert os.path.exists(path), f"Missing report: {path}"  # nosec: B101 - test assertion"
            print(f"[TEST] Found {ext.upper()}: {path}")

        print("[TEST] Integration smoke test PASSED")

    finally:
        # Cleanup: stop server and remove generated reports
        try:
            server_proc.terminate()
            server_proc.wait(timeout=5)
        except Exception:
            server_proc.kill()

        # Remove reports created by this test
        try:
            for ext in ("html", "json", "csv", "txt"):
                path = os.path.join("reports", f"{outname}.{ext}")
                if os.path.exists(path):
                    os.remove(path)
                    print(f"[TEST] Cleaned up {path}")
        except Exception as e:
            print(f"[TEST] Warning during cleanup: {e}")
