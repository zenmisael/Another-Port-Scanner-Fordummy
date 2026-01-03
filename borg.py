#!/usr/bin/env python3
import socket
import ssl
import time
from datetime import timedelta
import json
import argparse
import platform
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import sys

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

lock = threading.Lock()

# ---------------- PORTS ----------------
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
UDP_FAST = [53, 123, 161]
UDP_FULL = [53, 67, 68, 69, 123, 161, 500, 514]

# ---------------- PING & OS FP ----------------
def ping_ttl(ip):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", ip]
        else:
            cmd = ["ping", "-c", "1", ip]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            if "ttl=" in line.lower():
                return int(line.lower().split("ttl=")[1].split()[0])
    except:
        pass
    return None

def os_fingerprint(ip):
    ttl = ping_ttl(ip)
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux / Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device"

def is_host_alive(ip):
    try:
        return ping_ttl(ip) is not None
    except:
        return False

def ping_sweep(hosts):
    print("[*] Performing ping sweep...")
    alive = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(is_host_alive, h): h for h in hosts}
        for f in as_completed(futures):
            if f.result():
                alive.append(futures[f])
    print(f"[+] Alive hosts: {len(alive)}\n")
    return alive

# ---------------- TLS-CERT ----------------
def get_tls_cert(ip):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                cert = ss.getpeercert()
        return {
            "subject": dict(x[0] for x in cert["subject"]),
            "issuer": dict(x[0] for x in cert["issuer"]),
            "valid_from": cert["notBefore"],
            "valid_to": cert["notAfter"]
        }
    except:
        return None

# ---------------- BANNERS ----------------
def grab_tcp_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((ip, port))
            if port in (80, 443, 8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(1024).decode(errors="ignore").strip()
            return data if data else None
    except:
        return None

def grab_udp_banner(ip, port):
    probes = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        123: b"\x1b" + 47 * b"\0",
        161: b"\x30\x26\x02\x01\x01\x04\x06public"
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(probes.get(port, b"\x00"), (ip, port))
            data, _ = s.recvfrom(1024)
            return data.hex()[:80]
    except:
        return None

# ---------------- PROGRESS ----------------
def progress_bar(done, total, start):
    percent = done / total
    bar_len = 30
    filled = int(bar_len * percent)
    bar = "█" * filled + "-" * (bar_len - filled)
    elapsed = time.time() - start
    eta = (elapsed / done) * (total - done) if done else 0
    with lock:
        sys.stdout.write(
            f"\r[{bar}] {percent*100:5.1f}% | {done}/{total} | ETA {timedelta(seconds=int(eta))}"
        )
        sys.stdout.flush()

# ---------------- SCANS ----------------
def scan_tcp(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                return {
                    "protocol": "tcp",
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "banner": grab_tcp_banner(ip, port)
                }
    except:
        pass
    return None

def scan_udp(ip, port):
    banner = grab_udp_banner(ip, port)
    if banner:
        return {
            "protocol": "udp",
            "port": port,
            "service": COMMON_PORTS.get(port, "Unknown"),
            "banner": banner
        }
    return None

# ---------------- HOST SCAN ----------------
def scan_host(ip, fast):
    print(f"[+] Scanning {ip}")
    os_guess = os_fingerprint(ip)
    print(f"[OS] {os_guess}")
    print("{:<15} {:<5} {:<6} {:<12} {}".format("IP", "PROTO", "PORT", "SERVICE", "BANNER"))

    tcp_ports = list(COMMON_PORTS.keys()) if fast else range(1, 65536)
    udp_ports = UDP_FAST if fast else UDP_FULL

    tasks = []
    results = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=300 if fast else 150) as ex:
        for p in tcp_ports:
            tasks.append(ex.submit(scan_tcp, ip, p))
        for p in udp_ports:
            tasks.append(ex.submit(scan_udp, ip, p))

        total = len(tasks)
        done = 0

        for f in as_completed(tasks):
            res = f.result()
            done += 1
            if res:
                with lock:
                    results.append(res)
                    banner = res["banner"][:60] if res["banner"] else ""
                    print(f"{ip:<15} {res['protocol']:<5} {res['port']:<6} {res['service']:<12} {banner}")
            progress_bar(done, total, start)

    # TLS parsing
    if any(r["protocol"] == "tcp" and r["port"] == 443 for r in results):
        cert = get_tls_cert(ip)
        if cert:
            results.append({"tls_certificate": cert})

    print("\n")
    return {
        "os": os_guess,
        "services": results
    }

# ---------------- MAIN ----------------
def main(target, fast, combined):
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = ping_sweep([str(h) for h in net.hosts()])
    except ValueError:
        hosts = [socket.gethostbyname(target)]

    output = {}

    for host in hosts:
        output[host] = scan_host(host, fast)
        if not combined:
            with open(f"{host}.json", "w") as f:
                json.dump(output[host], f, indent=2)

    if combined:
        fname = f"subnet_{target.replace('/', '_')}.json"
        with open(fname, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[+] Combined results saved to {fname}")

# ---------------- Prelude ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced TCP/UDP Scanner")
    parser.add_argument("host", help="Target IP / domain / subnet")
    parser.add_argument("--fast", action="store_true", help="Fast scan")
    parser.add_argument("--combined", action="store_true", help="Single JSON output")
    args = parser.parse_args()

    main(args.host, args.fast, args.combined)
