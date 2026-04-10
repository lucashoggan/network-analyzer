#!/usr/bin/env python3
"""
pcap_to_csv.py

Converts a .pcap file into a CSV format compatible with the network-analyzer process.py schema.
Uses multiprocessing to parallelize packet dissection across all available CPU cores.

Requirements:
    scapy==2.5.0

Usage:
    pip install -r requirements.txt
    python pcap_to_csv.py input.pcap output.csv
"""

import argparse
import csv
import ipaddress
import multiprocessing as mp
import sys
from datetime import datetime, timezone

try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, IPv6
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.l2 import Ether
    from scapy.utils import RawPcapReader
except ImportError:
    print("Error: scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

# Number of packets sent to each worker at once.
# Higher = less IPC overhead; lower = more balanced load.
BATCH_SIZE = 1000


def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def determine_direction(src_ip: str, dst_ip: str) -> str:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private and not dst_private:
        return "outbound"
    elif not src_private and dst_private:
        return "inbound"
    return "mixed"


def process_batch(args: tuple) -> list[dict]:
    """
    Worker function. Receives a batch of (pkt_num, raw_bytes, timestamp) tuples
    plus the pcap link-layer type, parses them with scapy, and returns rows.
    """
    batch, linktype = args
    rows = []

    for pkt_num, raw_bytes, ts in batch:
        try:
            pkt = Ether(raw_bytes) if linktype == 1 else IP(raw_bytes)
        except Exception:
            continue

        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            continue

        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        timestamp = dt.isoformat().replace("+00:00", "Z")
        direction = determine_direction(src_ip, dst_ip)

        protocol = "other"
        port = ""
        domain = ""
        status = "success"
        is_auth = "false"
        auth_status = ""

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol = "tcp"
            port = str(tcp.dport)
            if tcp.flags & 0x04:  # RST flag
                status = "failed"
        elif pkt.haslayer(UDP):
            protocol = "udp"
            port = str(pkt[UDP].dport)

        if pkt.haslayer(DNS):
            protocol = "dns"
            if pkt.haslayer(DNSQR):
                try:
                    domain = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
                except Exception:
                    pass
            dns = pkt[DNS]
            if dns.qr == 1 and dns.rcode > 0:
                status = "failed"
        elif pkt.haslayer(HTTPRequest):
            protocol = "http"
            req = pkt[HTTPRequest]
            if hasattr(req, "Host") and req.Host:
                try:
                    domain = req.Host.decode("utf-8")
                except Exception:
                    pass
            if hasattr(req, "Authorization"):
                is_auth = "true"
        elif pkt.haslayer(HTTPResponse):
            protocol = "http"
            resp = pkt[HTTPResponse]
            if hasattr(resp, "Status_Code"):
                try:
                    code = int(resp.Status_Code)
                    if code >= 400:
                        status = "failed"
                    if code in (401, 403):
                        is_auth = "true"
                        auth_status = "failed"
                except Exception:
                    pass

        if port in ("80", "8080", "443") and protocol in ("tcp", "other"):
            protocol = "http"
        elif port == "53":
            protocol = "dns"

        rows.append({
            "packet_number": pkt_num,
            "timestamp": timestamp,
            "packets": 1,
            "bytes": len(raw_bytes),
            "direction": direction,
            "protocol": protocol,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "domain": domain,
            "status": status,
            "is_auth": is_auth,
            "auth_status": auth_status,
            "port": port,
            "tag": "",
        })

    return rows


def _batch_generator(input_pcap: str):
    """
    Yields (batch, linktype) tuples by reading raw packet bytes only —
    no scapy dissection happens here, keeping the main process fast.
    """
    with RawPcapReader(input_pcap) as reader:
        linktype = reader.linktype
        batch = []
        pkt_num = 0
        for raw_bytes, hdr in reader:
            pkt_num += 1
            ts = hdr.sec + hdr.usec / 1_000_000
            batch.append((pkt_num, raw_bytes, ts))
            if len(batch) >= BATCH_SIZE:
                yield (batch, linktype)
                batch = []
        if batch:
            yield (batch, linktype)


def process_pcap(input_pcap: str, output_csv: str):
    fieldnames = [
        "packet_number", "timestamp", "packets", "bytes", "direction",
        "protocol", "source_ip", "destination_ip", "domain", "status",
        "is_auth", "auth_status", "port", "tag",
    ]

    num_workers = mp.cpu_count()
    print(f"Processing {input_pcap} -> {output_csv}")
    print(f"Using {num_workers} worker processes (batch size: {BATCH_SIZE:,})")

    total = 0
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        with mp.Pool(num_workers) as pool:
            # imap preserves packet order; chunksize=4 amortizes IPC overhead
            for rows in pool.imap(process_batch, _batch_generator(input_pcap), chunksize=4):
                writer.writerows(rows)
                total += len(rows)
                if total % 50_000 < BATCH_SIZE:
                    print(f"  Written {total:,} rows...")

    print(f"Done. {total:,} packets written to {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PCAP to CSV for Network Analyzer")
    parser.add_argument("input_pcap", help="Path to the input .pcap file")
    parser.add_argument("output_csv", help="Path to the output .csv file")
    args = parser.parse_args()
    process_pcap(args.input_pcap, args.output_csv)
