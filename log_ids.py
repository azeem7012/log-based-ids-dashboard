import re
import json
import argparse
from collections import defaultdict

alerts = []

def log_alert(level, alert_type, src, message):
    alert = {
        "level": level,
        "type": alert_type,
        "source": src,
        "message": message
    }
    alerts.append(alert)
    print(f"🚨 ALERT: [{level}] [{alert_type}] SRC={src} | {message}")

# 🔐 Brute Force Detection
def detect_bruteforce(logs):
    print("\n[*] Running Brute-Force Detection...")
    failed_logins = defaultdict(int)

    for line in logs:
        match = re.search(r"Failed password.*from ([\w\.:]+)", line)
        if match:
            ip = match.group(1)
            failed_logins[ip] += 1

    for ip, count in failed_logins.items():
        if count >= 5:
            log_alert("HIGH", "BRUTE_FORCE", ip, f"{count} failed SSH login attempts")

# 🌐 Port Scan Detection
def detect_port_scan(logs):
    print("\n[*] Running Port Scan Detection...")
    ports_by_ip = defaultdict(set)

    for line in logs:
        match = re.search(r"connection from ([\w\.:]+).*port (\d+)", line)
        if match:
            ip = match.group(1)
            port = match.group(2)
            ports_by_ip[ip].add(port)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= 10:
            log_alert("MEDIUM", "PORT_SCAN", ip, f"Scanned {len(ports)} unique ports")

# 🌍 Web 404 Detection
def detect_404_spike(logs):
    print("\n[*] Running Excessive 404 Detection...")
    errors_by_ip = defaultdict(int)

    for line in logs:
        match = re.search(r"([\w\.:]+).*\"GET .*\" 404", line)
        if match:
            ip = match.group(1)
            errors_by_ip[ip] += 1

    for ip, count in errors_by_ip.items():
        if count >= 15:
            log_alert("MEDIUM", "EXCESSIVE_404", ip, f"{count} HTTP 404 responses")

# 🔥 NEW: Suspicious Login Detection
def detect_success_after_bruteforce(logs):
    print("\n[*] Running Suspicious Login Detection...")

    failed_ips = set()
    success_ips = set()

    for line in logs:
        fail = re.search(r"Failed password.*from ([\w\.:]+)", line)
        success = re.search(r"Accepted password.*from ([\w\.:]+)", line)

        if fail:
            failed_ips.add(fail.group(1))

        if success:
            success_ips.add(success.group(1))

    for ip in success_ips:
        if ip in failed_ips:
            log_alert("HIGH", "SUSPICIOUS_LOGIN", ip, "Login success after multiple failures")

# 📂 Load Logs
def load_logs(files):
    all_logs = []
    print("\n[*] Ingesting logs...")
    for file in files:
        print(f"  [+] Loading: {file}")
        try:
            with open(file, "r") as f:
                lines = f.readlines()
                all_logs.extend(lines)
        except FileNotFoundError:
            print(f"  [!] File not found: {file}")
    print(f"\n[*] Total lines loaded: {len(all_logs)}")
    return all_logs

# 🎮 Demo Logs
def generate_demo_logs():
    print("\n[*] DEMO MODE: Generating sample attack logs...")

    with open("demo_auth.log", "w") as f:
        for _ in range(8):
            f.write("Failed password for invalid user admin from 10.0.0.5 port 22 ssh2\n")

    with open("demo_syslog.log", "w") as f:
        for port in range(20, 32):
            f.write(f"connection from 10.0.0.9 port {port}\n")

    with open("demo_web.log", "w") as f:
        for _ in range(20):
            f.write('10.0.0.7 - - "GET /admin HTTP/1.1" 404\n')

    return ["demo_auth.log", "demo_syslog.log", "demo_web.log"]

# 💾 Save Results
def save_results():
    with open("ids_alerts.log", "w") as f:
        for alert in alerts:
            f.write(f"{alert}\n")

    with open("ids_report.json", "w") as f:
        json.dump(alerts, f, indent=4)

# 🧠 Main Function
def main():
    parser = argparse.ArgumentParser(description="Log-Based IDS")
    parser.add_argument("--demo", action="store_true", help="Run demo mode")
    args = parser.parse_args()

    print("=======================================================")
    print("   Log-Based Intrusion Detection System (IDS)")
    print("   Cloudisian Internal SOC Project")
    print("=======================================================")

    if args.demo:
        files = generate_demo_logs()
    else:
        print("[*] Using real system logs...")
        files = ["real_auth.log"]

    logs = load_logs(files)

    detect_bruteforce(logs)
    detect_success_after_bruteforce(logs)  # 🔥 NEW
    detect_port_scan(logs)
    detect_404_spike(logs)

    save_results()

    print("\n[*] Analysis complete.")
    print("[*] Alerts saved to ids_alerts.log")
    print("[*] JSON report saved to ids_report.json")

if __name__ == "__main__":
    main()
