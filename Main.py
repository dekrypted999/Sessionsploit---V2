#!/usr/bin/env python3
"""
ip_scanner.py - simple and safe IP reachability checker

Usage:
    python ip_scanner.py -p 80 192.168.1.1 8.8.8.8
    python ip_scanner.py -p 22 -f targets.txt

Only scan hosts you own or have permission to test.
"""

import argparse
import socket
import re
from concurrent.futures import ThreadPoolExecutor

def is_valid_ipv4(ip: str) -> bool:
    pattern = re.compile(r"""
        ^
        (?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)
        $
    """, re.VERBOSE)
    return bool(pattern.match(ip))

def read_ips_from_file(filename: str):
    ips = []
    try:
        with open(filename, "r") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    ips.append(ip)
    except Exception as e:
        print(f"Could not read file {filename}: {e}")
    return ips

def try_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except Exception:
        return False

def scan_ip(ip: str, port: int, timeout: float):
    if not is_valid_ipv4(ip):
        print(f"{ip:15} : invalid IPv4 address")
        return
    ok = try_connect(ip, port, timeout)
    status = "open/responding" if ok else "no response"
    print(f"{ip:15} : {status}")

def main():
    parser = argparse.ArgumentParser(description="Simple IP Scanner (safe version)")
    parser.add_argument("ips", nargs="*", help="List of IPs to scan")
    parser.add_argument("-p", "--port", type=int, default=80, help="Port to test (default: 80)")
    parser.add_argument("-t", "--timeout", type=float, default=0.3, help="Timeout in seconds (default: 0.3)")
    parser.add_argument("-f", "--file", help="File containing IPs, one per line")
    parser.add_argument("-j", "--threads", type=int, default=20, help="Number of concurrent threads")
    args = parser.parse_args()

    ips = args.ips
    if args.file:
        ips.extend(read_ips_from_file(args.file))

    if not ips:
        parser.print_help()
        return

    print(f"Scanning {len(ips)} hosts on port {args.port}...")
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for ip in ips:
            pool.submit(scan_ip, ip, args.port, args.timeout)

if __name__ == "__main__":
    main()

