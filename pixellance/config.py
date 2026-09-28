"""Global configuration and path resolution."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RESOURCE_DIR = BASE_DIR / "resource"
REPORT_DIR = BASE_DIR / "reports"

# nmap tuning
NMAP_TIMING = 4
NMAP_MIN_HOSTGROUP = 100
NMAP_SCRIPT_TIMEOUT = "20s"
NMAP_MAX_RETRIES = 2

# Ports of interest → trigger file names
# These map to discover's port-split files
HIGH_VALUE_TCP_PORTS = [
    13, 19, 21, 22, 23, 25, 37, 53, 67, 69, 70, 79, 80, 102, 110, 111,
    119, 123, 135, 137, 139, 143, 161, 389, 443, 445, 465, 500, 502,
    512, 513, 514, 523, 524, 548, 554, 563, 587, 623, 631, 636, 771,
    831, 873, 902, 993, 995, 998, 1050, 1080, 1099, 1158, 1344, 1352,
    1414, 1433, 1521, 1720, 1723, 1883, 1911, 1962, 2049, 2202, 2375,
    2628, 2947, 3000, 3031, 3050, 3260, 3306, 3310, 3389, 3500, 3632,
    4242, 4369, 4786, 5000, 5019, 5060, 5094, 5432, 5560, 5631, 5632,
    5666, 5672, 5850, 5900, 5920, 5984, 5985, 6000, 6001, 6002, 6003,
    6004, 6005, 6379, 6633, 6653, 6666, 7210, 7634, 7777, 8000, 8009,
    8080, 8081, 8091, 8140, 8222, 8332, 8333, 8400, 8443, 8834, 9000,
    9084, 9100, 9160, 9600, 9998, 9999, 10000, 10443, 10809, 11211,
    12000, 12345, 13364, 19150, 20256, 27017, 28784, 30718, 35871,
    37777, 46824, 49152, 50000, 50030, 50060, 50070, 50075, 50090,
    60010, 60030,
]

HIGH_VALUE_UDP_PORTS = [
    53, 67, 69, 123, 137, 161, 407, 500, 523, 623, 1434, 1604, 1900,
    2302, 2362, 3478, 3671, 4800, 5353, 5683, 6481, 17185, 31337,
    34964, 44818, 47808,
]

# Multi-port service aliases (combine multiple ports into one trigger file)
SERVICE_ALIASES = {
    "smtp": [25, 465, 587],
    "nntp": [119, 433, 563],
    "db2": [523],
    "bitcoin": [8332, 8333],
    "x11": [6000, 6001, 6002, 6003, 6004, 6005],
    "openflow": [6633, 6653],
    "hadoop": [50030, 50060, 50070, 50075, 50090],
    "apache-hbase": [60010, 60030],
}

# HexStrike AI server (https://github.com/0x4m4/hexstrike-ai)
# Point HEXSTRIKE_SERVER at your Kali VM, e.g. http://<vm-ip>:8888
HEXSTRIKE_SERVER = os.environ.get("HEXSTRIKE_SERVER", "http://127.0.0.1:8888")
HEXSTRIKE_TIMEOUT = int(os.environ.get("HEXSTRIKE_TIMEOUT", "600"))

# Web ports for URL extraction
HTTP_PORTS = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 3000, 5000, 5001, 8000,
    8008, 8080, 8081, 8443, 8834, 8888, 9000, 9084, 9090, 9443, 10000,
]
HTTPS_PORTS = [443, 8443, 9443, 10443]
