#!/usr/bin/env python3
"""Local server for the ShadowTrace Web Hub with offline security headers
and local ADB bridge endpoint for automatic Android device audits.

Usage:
    python web/serve.py [--port 8772]
"""
import argparse
import http.server
import json
import os
import shutil
import subprocess
import sys
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))


class WebHubHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HERE, **kwargs)

    def do_GET(self):
        # Local Android Scan API Bridge
        if self.path.startswith("/api/scan-android"):
            self.handle_android_scan()
            return
        if self.path.startswith("/api/download/"):
            self.handle_download()
            return
        super().do_GET()

    def handle_download(self):
        filename = os.path.basename(self.path.split("?")[0])
        root_dir = os.path.dirname(HERE)

        file_map = {
            "shadowtrace-toolkit.py": os.path.join(root_dir, "dist", "shadowtrace-toolkit.py"),
            "zero-breach-toolkit.py": os.path.join(root_dir, "dist", "zero-breach-toolkit.py"),
            "run-scan.cmd": os.path.join(root_dir, "scan", "run-scan.cmd"),
            "run-scan.sh": os.path.join(root_dir, "scan", "run-scan.sh"),
            "shadowtrace-toolkit.exe": os.path.join(root_dir, "dist", "shadowtrace-toolkit.exe"),
        }

        filepath = file_map.get(filename)
        if not filepath or not os.path.isfile(filepath):
            self.send_error(404, f"File {filename} not found.")
            return

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(500, str(e))

    def send_json(self, response_data, status=200):
        payload = json.dumps(response_data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(payload)

    def handle_android_scan(self):
        """Automatically queries connected Android devices for all third-party packages,
        permissions, accessibility services, and system properties."""
        adb_path = shutil.which("adb")
        if not adb_path:
            # Check common Android SDK locations
            candidates = [
                os.path.expanduser("~/AppData/Local/Android/Sdk/platform-tools/adb.exe"),
                os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
                "/usr/bin/adb",
                "/usr/local/bin/adb",
            ]
            for c in candidates:
                if os.path.isfile(c) and os.access(c, os.X_OK):
                    adb_path = c
                    break

        if not adb_path:
            self.send_json({
                "ok": False,
                "error": "adb binary not found in PATH or standard SDK folders. Use WebUSB direct connect."
            })
            return

        try:
            cflags = 0x08000000 if sys.platform == "win32" else 0
            # Check for connected devices
            devices_proc = subprocess.run(
                [adb_path, "devices"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                creationflags=cflags,
                timeout=8
            )
            lines = [l.strip() for l in devices_proc.stdout.splitlines() if l.strip() and not l.startswith("List of")]
            active = [l for l in lines if "\tdevice" in l]

            if not active:
                msg = "No authorized device connected."
                if any("unauthorized" in l for l in lines):
                    msg = "Device connected but unauthorized. Tap 'Allow USB debugging' on your phone."
                self.send_json({"ok": False, "error": msg, "devices": lines})
                return

            device_serial = active[0].split("\t")[0]

            # Execute comprehensive package and security audit command
            cmd = (
                "pm list packages -3 -f -i; "
                "echo '===SECTION==='; "
                "pm list packages -u; "
                "echo '===SECTION==='; "
                "settings get secure enabled_accessibility_services; "
                "echo '===SECTION==='; "
                "dumpsys device_policy | grep -E '(ComponentInfo|admin=)'; "
                "echo '===SECTION==='; "
                "getprop ro.build.version.security_patch; "
                "getprop ro.boot.verifiedbootstate; "
                "getprop ro.build.tags; "
                "getprop ro.product.model; "
                "getprop ro.build.version.release"
            )

            res = subprocess.run(
                [adb_path, "-s", device_serial, "shell", cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                creationflags=cflags,
                timeout=25
            )
            if res.returncode != 0:
                self.send_json({"ok": False, "error": f"ADB shell command failed: {res.stderr}"})
                return

            self.send_json({
                "ok": True,
                "source": "adb-bridge",
                "serial": device_serial,
                "raw": res.stdout
            })

        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)})

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description="Serve the ShadowTrace Web Hub locally.")
    parser.add_argument("--port", type=int, default=8772, help="Port to listen on (default: 8772)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    server_address = ("127.0.0.1", args.port)
    httpd = http.server.HTTPServer(server_address, WebHubHandler)
    url = f"http://127.0.0.1:{args.port}/index.html"

    print("=" * 64)
    print("  ShadowTrace Web Hub running locally")
    print(f"  URL: {url}")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
