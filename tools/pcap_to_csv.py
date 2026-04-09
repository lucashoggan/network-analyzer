#!/usr/bin/env python3
"""
pcap_to_csv.py

Converts a .pcap file into a CSV format compatible with the network-analyzer process.py schema.

Requirements (save as requirements.txt in the same directory):
scapy==2.5.0

Usage:
    pip install -r requirements.txt
    python pcap_to_csv.py input.pcap output.csv
"""

import argparse
import csv
import ipaddress
import sys
from datetime import datetime, timezone

# Import scapy modules
try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, IPv6
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.utils import PcapReader
except ImportError:
    print("Error: scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private (RFC 1918)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def determine_direction(src_ip: str, dst_ip: str) -> str:
    """
    Heuristic to determine traffic direction based on private/public IP addresses.
    If source is private and destination is public -> outbound
    If source is public and destination is private -> inbound
    Otherwise -> mixed
    """
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)

    if src_private and not dst_private:
        return "outbound"
    elif not src_private and dst_private:
        return "inbound"
    return "mixed"


def process_pcap(input_pcap: str, output_csv: str):
    """Reads a PCAP file and writes the extracted data to a CSV."""

    fieldnames = [
        "timestamp",
        "packets",
        "bytes",
        "direction",
        "protocol",
        "source_ip",
        "destination_ip",
        "domain",
        "status",
        "is_auth",
        "auth_status",
        "port",
        "tag",
    ]

    print(f"Processing {input_pcap} -> {output_csv}...")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        # Use PcapReader to stream the file instead of loading it all into memory
        with PcapReader(input_pcap) as pcap_reader:
            for pkt_num, pkt in enumerate(pcap_reader, 1):
                # We only care about IP traffic for this schema
                if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                    continue

                ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # 1. Timestamp & Basic Stats
                # Convert packet time to ISO 8601 UTC
                dt = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
                timestamp = dt.isoformat().replace("+00:00", "Z")

                pkt_bytes = len(pkt)
                direction = determine_direction(src_ip, dst_ip)

                # Defaults
                protocol = "other"
                port = ""
                domain = ""
                status = "success"
                is_auth = "false"
                auth_status = ""

                # 2. Transport Layer (TCP / UDP)
                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    protocol = "tcp"
                    # Use destination port as the primary service port
                    port = str(tcp_layer.dport)

                    # Check for TCP RST (Reset) flag which indicates a failed/rejected connection
                    if tcp_layer.flags & 0x04:
                        status = "failed"

                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    protocol = "udp"
                    port = str(udp_layer.dport)

                # 3. Application Layer (DNS / HTTP)
                if pkt.haslayer(DNS):
                    protocol = "dns"
                    dns_layer = pkt[DNS]

                    # Extract queried domain name
                    if pkt.haslayer(DNSQR):
                        try:
                            qname = pkt[DNSQR].qname.decode("utf-8")
                            domain = qname.rstrip(".")  # Remove trailing dot
                        except Exception:
                            pass

                    # Check DNS response code (0 is NOERROR, >0 is an error like NXDOMAIN)
                    if dns_layer.qr == 1 and dns_layer.rcode > 0:
                        status = "failed"

                elif pkt.haslayer(HTTPRequest):
                    protocol = "http"
                    http_req = pkt[HTTPRequest]

                    if hasattr(http_req, "Host") and http_req.Host:
                        try:
                            domain = http_req.Host.decode("utf-8")
                        except Exception:
                            pass

                    # Check for authentication headers
                    if hasattr(http_req, "Authorization"):
                        is_auth = "true"

                elif pkt.haslayer(HTTPResponse):
                    protocol = "http"
                    http_resp = pkt[HTTPResponse]

                    if hasattr(http_resp, "Status_Code"):
                        try:
                            status_code = int(http_resp.Status_Code)
                            if status_code >= 400:
                                status = "failed"

                            # 401 Unauthorized indicates failed authentication
                            if status_code == 401:
                                is_auth = "true"
                                auth_status = "failed"
                            # 200 OK after an auth attempt could be success, but hard to link statelessly.
                            # We'll flag 403 as potential auth failure as well.
                            elif status_code == 403:
                                is_auth = "true"
                                auth_status = "failed"
                        except Exception:
                            pass

                # Fallback port inference for common protocols if not explicitly caught
                if port == "80" or port == "8080" or port == "443":
                    if protocol in ("tcp", "other"):
                        protocol = "http"  # Grouping HTTPS under HTTP for simplicity in this schema
                elif port == "53":
                    protocol = "dns"

                # Construct row
                row = {
                    "timestamp": timestamp,
                    "packets": 1,
                    "bytes": pkt_bytes,
                    "direction": direction,
                    "protocol": protocol,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "domain": domain,
                    "status": status,
                    "is_auth": is_auth,
                    "auth_status": auth_status,
                    "port": port,
                    "tag": "",  # Explicitly left blank as requested
                }

                writer.writerow(row)

                if pkt_num % 10000 == 0:
                    print(f"Processed {pkt_num} packets...")

    print(f"Finished processing. Output saved to {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert PCAP to CSV for Network Analyzer"
    )
    parser.add_argument("input_pcap", help="Path to the input .pcap file")
    parser.add_argument("output_csv", help="Path to the output .csv file")

    args = parser.parse_args()

    process_pcap(args.input_pcap, args.output_csv)
