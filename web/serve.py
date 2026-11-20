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
import time
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
        # Local Home & IoT Network Audit API
        if self.path.startswith("/api/scan-network"):
            self.handle_network_scan()
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
                "getprop"
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

    def handle_network_scan(self):
        """Audits the local RFC 1918 network and IoT devices using homenet."""
        try:
            root_dir = os.path.dirname(HERE)
            scan_dir = os.path.join(root_dir, "scan")
            if scan_dir not in sys.path:
                sys.path.insert(0, scan_dir)

            from zbtriage import homenet

            # Run homenet audit (read-only, RFC 1918, camera check, no public lookups)
            res = homenet.hn_check(emit=lambda x: None, router_lookups=False, camera_check=True)

            # Enrich devices with classifications, icons, and risk levels
            devices = []
            camera_count = 0
            tv_count = 0
            iot_count = 0
            pc_count = 0
            router_count = 0
            risky_doors_count = 0
            critical_risks = 0

            for d in res.get("devices", []):
                ports = d.get("ports", [])
                kind = (d.get("kind") or "").lower()
                name = (d.get("name") or "").lower()
                maker = (d.get("maker") or "").lower()
                model = (d.get("model") or "").lower()

                # Determine category & icon
                cat = "device"
                icon = "📱"

                is_cam = (554 in ports or 8000 in ports or 34567 in ports or 37777 in ports
                          or "camera" in kind or "camera" in name or "webcam" in name
                          or "nvr" in name or "dvr" in name or "hikvision" in maker or "dahua" in maker)
                is_tv = (8008 in ports or 8009 in ports or "tv" in kind or "googlecast" in kind
                         or "airplay" in kind or "tv" in name or "cast" in name or "roku" in name)
                is_router = (d.get("ip") == res.get("router") or kind == "router"
                             or "router" in maker or "gateway" in name or "mikrotik" in maker)
                is_iot = (1883 in ports or "speaker" in kind or "hue" in kind or "accessory" in kind
                          or "sonos" in kind or "alexa" in kind or "tuya" in maker or "sonoff" in maker)
                is_printer = (631 in ports or 9100 in ports or kind == "printer" or "printer" in name)
                is_pc = (445 in ports or 3389 in ports or 22 in ports or 5900 in ports
                         or "computer" in kind or "dell" in maker or "lenovo" in maker or "hp" in maker
                         or "intel" in maker or "apple" in maker)

                if is_router:
                    cat = "router"
                    icon = "🌐"
                    router_count += 1
                elif is_cam:
                    cat = "camera"
                    icon = "📹"
                    camera_count += 1
                elif is_tv:
                    cat = "tv"
                    icon = "📺"
                    tv_count += 1
                elif is_iot:
                    cat = "iot"
                    icon = "💡"
                    iot_count += 1
                elif is_printer:
                    cat = "printer"
                    icon = "🖨️"
                elif is_pc:
                    cat = "computer"
                    icon = "💻"
                    pc_count += 1

                # Port descriptions and risk mapping
                ports_detail = []
                dev_risks = []
                dev_level = "clean"

                for p in ports:
                    p_info = homenet.HN_PORTS.get(p, ("open port", None))
                    p_name = p_info[0]
                    p_risk = p_info[1]
                    ports_detail.append({"port": p, "name": p_name, "risk": p_risk})
                    if p_risk:
                        risky_doors_count += 1
                        dev_risks.append(f"Port {p} ({p_name}): {p_risk}")

                # Camera RTSP password check
                video_auth = d.get("video_password")
                if video_auth == "open":
                    dev_level = "critical"
                    critical_risks += 1
                    dev_risks.append("CRITICAL: Camera RTSP stream (port 554) is broadcast openly WITHOUT a password! Anyone on your local network can watch your live camera feed.")
                elif 23 in ports:
                    dev_level = "critical"
                    critical_risks += 1
                    dev_risks.append("CRITICAL: Unencrypted Telnet service (port 23) is running. Commonly targeted by IoT botnets (Mirai) using factory default passwords.")
                elif 5555 in ports:
                    dev_level = "critical"
                    critical_risks += 1
                    dev_risks.append("CRITICAL: Android Debug Bridge (ADB) over network (port 5555) is open without authentication. Anyone on this network can install apps, dump screen contents, or execute commands on this device.")
                elif dev_risks or d.get("exploited"):
                    dev_level = "warn"
                elif ports:
                    dev_level = "info"

                devices.append({
                    "ip": d.get("ip"),
                    "mac": d.get("mac"),
                    "name": d.get("name") or (f"Router ({d.get('maker')})" if is_router else ""),
                    "model": d.get("model") or "",
                    "maker": d.get("maker") or "",
                    "kind": d.get("kind") or cat,
                    "category": cat,
                    "icon": icon,
                    "ports": ports,
                    "ports_detail": ports_detail,
                    "video_password": video_auth,
                    "level": dev_level,
                    "risks": dev_risks,
                    "exploited": d.get("exploited"),
                    "shared_mac": d.get("shared_mac", False)
                })

            port_mappings = res.get("port_mappings", [])
            pinholes_count = len(port_mappings)

            # Posture Score calculation (100 base)
            score = 100
            score -= (critical_risks * 25)
            score -= (pinholes_count * 15)
            score -= (max(0, risky_doors_count - critical_risks) * 10)
            score = max(10, min(100, score))

            if score >= 95:
                grade = "A+"
                posture_verdict = "EXCELLENT POSTURE: LOCAL DOORS SECURED"
                posture_class = "clean"
            elif score >= 85:
                grade = "A"
                posture_verdict = "GOOD POSTURE: MINIMAL EXPOSURE"
                posture_class = "clean"
            elif score >= 70:
                grade = "B"
                posture_verdict = "MODERATE POSTURE: SOME RISKY DOORS DETECTED"
                posture_class = "warn"
            elif score >= 50:
                grade = "C"
                posture_verdict = "POOR POSTURE: MULTIPLE RISKY PORTS EXPOSED"
                posture_class = "warn"
            else:
                grade = "F"
                posture_verdict = "CRITICAL RISKS DETECTED ON LOCAL NETWORK"
                posture_class = "bad"

            recommendations = []
            if critical_risks > 0:
                recommendations.append("Immediately review devices with open RTSP video feeds, Telnet, or network ADB (port 5555) and set strong passwords or disable debug modes.")
            if pinholes_count > 0:
                recommendations.append(f"Your router has {pinholes_count} UPnP port mapping(s) opened to the public internet. If not explicitly needed for gaming or self-hosting, disable UPnP in your router admin settings.")
            if camera_count > 0:
                recommendations.append("Place security cameras and video recorders on an isolated guest Wi-Fi network or separate IoT VLAN so they cannot access home computers.")
            if not recommendations:
                recommendations.append("Local network hygiene is strong. Keep router firmware updated and audit guest device connections periodically.")

            payload = {
                "ok": True,
                "timestamp": int(time.time() * 1000),
                "subnet": res.get("subnet"),
                "this_computer": res.get("this_computer"),
                "router": res.get("router"),
                "note": res.get("note", ""),
                "devices": devices,
                "port_mappings": port_mappings,
                "findings": res.get("findings", []),
                "gaps": res.get("gaps", []),
                "summary": {
                    "total_devices": len(devices),
                    "cameras": camera_count,
                    "tvs": tv_count,
                    "iot": iot_count,
                    "computers": pc_count,
                    "routers": router_count,
                    "risky_doors": risky_doors_count,
                    "pinholes": pinholes_count,
                    "critical_risks": critical_risks,
                    "score": score,
                    "grade": grade,
                    "posture_verdict": posture_verdict,
                    "posture_class": posture_class,
                    "recommendations": recommendations
                }
            }
            self.send_json(payload)

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
