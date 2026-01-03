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
    7: "Echo",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    500: "ISAKMP",
    514: "Syslog",
    520: "RIP",
    587: "SMTP (TLS)",
    631: "IPP Printer",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1701: "L2TP",
    1723: "PPTP",
    1812: "RADIUS",
    1813: "RADIUS Accounting",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2086: "WHM",
    2087: "WHM SSL",
    2181: "ZooKeeper",
    2222: "Direct Admin Panel",
    2375: "Docker API",
    2376: "Docker API TLS",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB HTTP",
    3000: "Custom App / Dev",
    3306: "MySQL",
    3389: "RDP",
    4000: "Custom App / Dev",
    4444: "Metasploit / Custom",
    5000: "Custom App / Dev",
    5432: "PostgreSQL",
    5500: "VNC",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    7001: "WebLogic",
    7077: "Resin / Java",
    7474: "Neo4j",
    8000: "Custom App / Dev",
    8009: "AJP",
    8080: "HTTP Alt",
    8081: "HTTP Alt 2",
    8443: "plesk",
    8888: "HTTP Alt 3",
    9000: "FastCGI",
    9042: "Cassandra",
    9060: "JBoss",
    9090: "Portainer / Custom",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    10000: "Webmin",
    11211: "Memcached",
    15672: "RabbitMQ",
    27017: "MongoDB",
    50030: "Hadoop",
    50070: "Hadoop NameNode",
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
