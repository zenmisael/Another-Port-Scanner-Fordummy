#!/usr/bin/env python3
import socket
import time
from datetime import timedelta
import json
import argparse
import platform
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# ---------------- LOGO ----------------
logo = """
 ____   ___  ____   ____   _      __        __    _       _     _             
| __ ) / _ \\|  _ \\ / ___| (_)___  \\ \\      / /_ _| |_ ___| |__ (_)_ __   __ _ 
|  _ \\| | | | |_) | |  _  | / __|  \\ \\ /\\ / / _` | __/ __| '_ \\| | '_ \\ / _` |
| |_) | |_| |  _ <| |_| | | \\__ \\   \\ V  V / (_| | || (__| | | | | | | | (_| |
|____/ \\___/|_| \\_\\\\____| |_|___/    \\_/\\_/ \\__,_|\\__\\___|_| |_|_|_| |_|\\__, |
                                                                        |___/
MADE By BORG
"""
print(logo)

# ---------------- COMMON PORTS ----------------
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alt",
    27017: "MongoDB",
}

lock = threading.Lock()
OS = platform.system()

# ---------------- PROGRESS BAR ----------------
def progress_bar(done, total, start):
    percent = done / total
    bar_len = 30
    filled = int(bar_len * percent)
    bar = "█" * filled + "-" * (bar_len - filled)

    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0

    msg = f"[{bar}] {percent*100:5.1f}% | {done}/{total} | ETA {timedelta(seconds=int(eta))}"

    with lock:
        sys.stdout.write("\r" + msg)
        sys.stdout.flush()

# ---------------- PORT SCAN ----------------
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((ip, port)) == 0:
                return {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown")
                }
    except:
        pass
    return None

# ---------------- HOST SCAN ----------------
def scan_host(ip, ports, fast):
    print(f"\n[+] Scanning host: {ip}")
    print("{:<15} {:<6} {}".format("IP", "PORT", "SERVICE"))

    results = []
    total = len(ports)
    done = 0
    start = time.time()

    workers = 300 if fast else 150

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, ip, p) for p in ports]

        for f in as_completed(futures):
            res = f.result()
            done += 1

            if res:
                with lock:
                    results.append(res)
                    print(f"{ip:<15} {res['port']:<6} {res['service']}")

            progress_bar(done, total, start)

    print()  # newline after progress bar
    print(f"[+] {ip} completed — {len(results)} open ports\n")
    return results

# ---------------- MAIN ----------------
def main(target, fast, combined):
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in network.hosts()]
        print(f"[+] Subnet detected: {network} ({len(hosts)} hosts)\n")
    except ValueError:
        ip = socket.gethostbyname(target)
        hosts = [ip]

    ports = list(COMMON_PORTS.keys()) if fast else list(range(1, 65536))
    output = {}

    for host in hosts:
        result = scan_host(host, ports, fast)
        output[host] = result

        if not combined:
            with open(f"{host}.json", "w") as f:
                json.dump(result, f, indent=2)

    if combined:
        filename = f"subnet_{target.replace('/', '_')}.json"
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Combined results saved to {filename}")

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced TCP Port Scanner (Subnet + Fast + Progress)"
    )
    parser.add_argument("host", help="Target IP, domain, or subnet (CIDR)")
    parser.add_argument("--fast", action="store_true", help="Fast scan (common ports only)")
    parser.add_argument("--combined", action="store_true", help="Single JSON output for whole subnet")

    args = parser.parse_args()
    main(args.host, args.fast, args.combined)
