import csv
from datetime import datetime
from os import environ
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from openai import OpenAI

OPENROUTER_KEY = environ.get("OPENROUTER_KEY")

openrouter_client = OpenAI(
    base_url="https://openrouter.ai/api/v1", api_key=OPENROUTER_KEY
)


# OpenRouter API functions
def get_embedding(text: str) -> List[float]:
    embedding = openrouter_client.embeddings.create(
        model="openai/text-embedding-3-small", input=text, encoding_format="float"
    )
    return embedding.data[0].embedding


# CSV functions
def validate_csv_headers(file_path: str) -> bool:
    """
    Checks if the CSV file has the required headers.
    """
    required_headers = {
        "packet_number",
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
    }
    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = set(next(reader))
            return required_headers.issubset(headers)
    except (FileNotFoundError, StopIteration, Exception):
        return False


def process_network_data(data: Dict[str, Any]) -> Tuple[str, Tuple[int, int]]:
    """
    Transforms structured network data into a natural language summary.
    """

    # Extract sections with defaults to avoid KeyErrors
    time_window = data.get("time_window", {})
    traffic = data.get("traffic", {})
    protocols = data.get("protocols", {})
    destinations = data.get("destinations", {})
    requests = data.get("requests", {})
    auth = data.get("authentication", {})
    ports = data.get("ports", {})
    flags = data.get("optional_flags", [])
    start_pkt_number = data.get("start_pkt_number", -1)
    end_pkt_number = data.get("end_pkt_number", -1)

    # --- 1. Traffic Summary ---
    total_packets = traffic.get("total_packets", 0)
    total_bytes = traffic.get("total_bytes", 0)
    direction = traffic.get("direction", "mixed")

    start_str = time_window.get("start", "")
    end_str = time_window.get("end", "")
    duration_seconds = 1.0
    if start_str and end_str:
        try:
            start_ts = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            end_ts = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
            duration_seconds = max((end_ts - start_ts).total_seconds(), 1.0)
        except ValueError:
            pass

    # Determine intensity based on packet rate
    packets_per_second = total_packets / duration_seconds
    if packets_per_second > 1000:
        intensity = "High"
    elif packets_per_second > 100:
        intensity = "Moderate"
    else:
        intensity = "Low"

    traffic_summary = (
        f"{intensity} traffic volume with {total_packets} packets and {total_bytes} bytes transferred over {duration_seconds:.2f} seconds ({packets_per_second:.2f} packets/sec).\n"
        f"Traffic is primarily {direction}."
    )

    # --- 2. Protocol Activity ---
    http = protocols.get("http", 0)
    dns = protocols.get("dns", 0)
    tcp = protocols.get("tcp", 0)
    udp = protocols.get("udp", 0)

    proto_counts = {"HTTP": http, "DNS": dns, "TCP": tcp, "UDP": udp}
    # Find the dominant protocol (highest count)
    if any(proto_counts.values()):
        dominant_protocol = max(proto_counts, key=lambda k: proto_counts[k])
    else:
        dominant_protocol = "None"

    protocol_activity = (
        f"Protocol usage includes HTTP ({http}), DNS ({dns}), TCP ({tcp}), UDP ({udp}).\n"
        f"Primary protocol is {dominant_protocol}."
    )

    # --- 3. Destination Behaviour ---
    unique_dest_ips = destinations.get("unique_destination_ips", 0)
    unique_domains = destinations.get("unique_domains", 0)

    domains_per_minute = (unique_domains / duration_seconds) * 60
    if domains_per_minute > 50:
        domain_level = "high"
    elif domains_per_minute > 10:
        domain_level = "moderate"
    else:
        domain_level = "low"

    destination_behaviour = (
        f"Client contacted {unique_dest_ips} destination IPs and {unique_domains} domains ({domains_per_minute:.2f} domains/min).\n"
        f"Number of unique domains is {domain_level}."
    )

    # --- 4. Request Dynamics ---
    rps = requests.get("requests_per_second", 0)

    if rps > 100:
        request_rate_level = "high"
    elif rps > 10:
        request_rate_level = "moderate"
    else:
        request_rate_level = "low"

    burstiness = "bursty" if "bursty" in flags else "steady"

    request_dynamics = (
        f"Request rate is {request_rate_level} at {rps} requests per second.\n"
        f"Traffic pattern is {burstiness}."
    )

    # --- 5. Authentication Signals ---
    attempts = auth.get("attempts", 0)
    failures = auth.get("failures", 0)

    auth_failures_per_minute = (failures / duration_seconds) * 60
    if attempts == 0:
        auth_note = "No authentication activity observed."
    elif auth_failures_per_minute > 5 and failures >= (attempts * 0.5):
        auth_note = "High number of authentication failures detected."
    else:
        auth_note = "Authentication activity present."

    authentication_signals = (
        f"Authentication activity shows {attempts} attempts with {failures} failures ({auth_failures_per_minute:.2f} failures/min).\n"
        f"{auth_note}"
    )

    # --- 6. Port Behaviour ---
    unique_ports = ports.get("unique_ports", 0)
    port_distribution = ports.get("port_distribution", "concentrated")
    ports_per_minute = (unique_ports / duration_seconds) * 60

    port_behaviour = (
        f"Connection attempts span {unique_ports} ports ({ports_per_minute:.2f} ports/min).\n"
        f"Port usage is {port_distribution}."
    )

    # --- 7. Behavioural Summary ---
    # Vocabulary constraints: Must use predefined vocabulary, 2-5 behaviours
    behaviors = []

    if intensity == "High":
        behaviors.append("high traffic volume")
    if domain_level == "high":
        behaviors.append("extensive domain querying")
    if auth_note == "High number of authentication failures detected.":
        behaviors.append("potential brute force")
    if port_distribution == "distributed":
        behaviors.append("port scanning pattern")
    if dominant_protocol == "DNS":
        behaviors.append("DNS heavy traffic")

    # Ensure we meet the minimum constraint of 2 behaviours
    if not behaviors:
        behaviors = ["standard traffic", "expected protocol usage"]
    elif len(behaviors) < 2:
        behaviors.append("standard traffic")

    # Ensure we meet the maximum constraint of 5 behaviours
    behaviors = behaviors[:5]

    behavioural_summary = f"Observed behaviours include: {', '.join(behaviors)}."

    # --- Final Output Assembly ---
    output = (
        f"{traffic_summary}\n\n"
        f"{protocol_activity}\n\n"
        f"{destination_behaviour}\n\n"
        f"{request_dynamics}\n\n"
        f"{authentication_signals}\n\n"
        f"{port_behaviour}\n\n"
        f"{behavioural_summary}"
    )

    return (output, (start_pkt_number, end_pkt_number))


def parse_network_csv(csv_lines: List[str]) -> Dict[str, Any]:
    """
    Parses a list of CSV lines and aggregates them into a dictionary.
    """
    total_packets = 0
    total_bytes = 0
    directions = {"inbound": 0, "outbound": 0}
    protocols = {"http": 0, "dns": 0, "tcp": 0, "udp": 0, "other": 0}
    source_ips = set()
    destination_ips = set()
    domains = set()
    total_requests = 0
    successful_connections = 0
    failed_connections = 0
    auth_attempts = 0
    auth_failures = 0
    ports_set = set()
    tags = set()
    timestamps = []
    start_packet_number: int | None = None
    end_packet_number: int = -1

    reader = csv.DictReader(csv_lines)
    for row in reader:
        packet_num = row.get("packet_number")
        if packet_num and not start_packet_number:
            start_packet_number = int(packet_num)
        if packet_num:
            end_packet_number = int(packet_num)

        total_requests += 1

        ts_str = row.get("timestamp", "")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                timestamps.append(ts)
            except ValueError:
                pass

        try:
            total_packets += int(row.get("packets", 0))
        except ValueError:
            pass

        try:
            total_bytes += int(row.get("bytes", 0))
        except ValueError:
            pass

        direction = row.get("direction", "").lower()
        if direction in directions:
            directions[direction] += 1

        protocol = row.get("protocol", "").lower()
        if protocol in protocols:
            protocols[protocol] += 1
        else:
            protocols["other"] += 1

        src_ip = row.get("source_ip", "")
        if src_ip:
            source_ips.add(src_ip)

        dst_ip = row.get("destination_ip", "")
        if dst_ip:
            destination_ips.add(dst_ip)

        domain = row.get("domain", "")
        if domain:
            domains.add(domain)

        status = row.get("status", "").lower()
        if status == "success":
            successful_connections += 1
        elif status == "failed":
            failed_connections += 1

        is_auth = row.get("is_auth", "").lower() in ("true", "1", "yes")
        if is_auth:
            auth_attempts += 1
            auth_status = row.get("auth_status", "").lower()
            if auth_status == "failed":
                auth_failures += 1

        port = row.get("port", "")
        if port:
            ports_set.add(port)

        tag = row.get("tag", "")
        if tag:
            tags.add(tag)

    start_time = min(timestamps) if timestamps else None
    end_time = max(timestamps) if timestamps else None
    duration_seconds = (
        (end_time - start_time).total_seconds() if (start_time and end_time) else 0
    )
    requests_per_second = (
        total_requests / duration_seconds
        if duration_seconds > 0
        else (total_requests if total_requests > 0 else 0)
    )

    overall_direction = "mixed"
    if directions["inbound"] > 0 and directions["outbound"] == 0:
        overall_direction = "inbound"
    elif directions["outbound"] > 0 and directions["inbound"] == 0:
        overall_direction = "outbound"

    return {
        "time_window": {
            "start": start_time.isoformat() if start_time else "",
            "end": end_time.isoformat() if end_time else "",
        },
        "traffic": {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "direction": overall_direction,
        },
        "protocols": protocols,
        "destinations": {
            "unique_source_ips": len(source_ips),
            "unique_destination_ips": len(destination_ips),
            "unique_domains": len(domains),
        },
        "requests": {
            "total_requests": total_requests,
            "requests_per_second": round(requests_per_second, 2),
        },
        "connections": {
            "successful": successful_connections,
            "failed": failed_connections,
        },
        "authentication": {"attempts": auth_attempts, "failures": auth_failures},
        "ports": {
            "unique_ports": len(ports_set),
            "port_distribution": "distributed"
            if (
                len(ports_set) / duration_seconds * 60
                if duration_seconds > 0
                else len(ports_set)
            )
            > 100
            else "concentrated",
        },
        "optional_flags": list(tags),
        "start_pkt_number": start_packet_number,
        "end_ptk_number": end_packet_number,
    }


def _process_csv_file(
    file_path: str,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Any],
    batch_size: Optional[int] = None,
    timeframe_seconds: Optional[int] = None,
) -> None:
    """
    Opens a CSV file and processes it in batches based on line count or timeframe.
    """
    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

        if batch_size:
            batch = []
            for row in reader:
                batch.append(row)
                if len(batch) >= batch_size:
                    lines = [",".join(header)] + [",".join(r) for r in batch]
                    data = parse_network_csv(lines)
                    on_complete(process_network_data(data))
                    batch = []
            if batch:
                lines = [",".join(header)] + [",".join(r) for r in batch]
                data = parse_network_csv(lines)
                on_complete(process_network_data(data))

        elif timeframe_seconds:
            current_batch = []
            start_ts = None

            for row in reader:
                row_dict = dict(zip(header, row))
                ts_str = row_dict.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    continue

                if start_ts is None:
                    start_ts = ts

                if (ts - start_ts).total_seconds() >= timeframe_seconds:
                    lines = [",".join(header)] + [",".join(r) for r in current_batch]
                    data = parse_network_csv(lines)
                    on_complete(process_network_data(data))
                    current_batch = [row]
                    start_ts = ts
                else:
                    current_batch.append(row)

            if current_batch:
                lines = [",".join(header)] + [",".join(r) for r in current_batch]
                data = parse_network_csv(lines)
                on_complete(process_network_data(data))


def batch_csv_to_nl(
    file_path: str,
    batch_size: int,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Any],
):
    """
    Opens csv file, turns batches of requests into natural language and calls on_complete on every branch
    """
    _process_csv_file(file_path, on_complete, batch_size=batch_size)


def batch_csv_to_nl_arr(
    file_path: str, batch_size: int
) -> List[Tuple[str, Tuple[int, int]]]:
    """
    Opens csv file, turns batches of requests into natural language and returns an array of all the outputs
    """
    out: List[Tuple[str, Tuple[int, int]]] = []
    batch_csv_to_nl(file_path, batch_size, lambda x: out.append(x))
    return out


def timeframe_csv_to_nl(
    file_path: str,
    timeframe_seconds: int,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Any],
):
    """
    Opens csv file, turns lines in a timeframe into natural language and calls on_complete on every branch
    """
    _process_csv_file(file_path, on_complete, timeframe_seconds=timeframe_seconds)


def timeframe_csv_to_nl_arr(
    file_path: str, timeframe_seconds: int
) -> List[Tuple[str, Tuple[int, int]]]:
    """
    Opens csv file, turns lines in a timeframe into natural language and returns an array of all the outputs
    """
    out: List[Tuple[str, Tuple[int, int]]] = []
    timeframe_csv_to_nl(file_path, timeframe_seconds, lambda x: out.append(x))
    return out


async def _process_csv_file_async(
    file_path: str,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Awaitable[Any]],
    batch_size: Optional[int] = None,
    timeframe_seconds: Optional[int] = None,
) -> None:
    """
    Async copy of the CSV file processor that awaits the callback.
    """
    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

        if batch_size:
            batch = []
            for row in reader:
                batch.append(row)
                if len(batch) >= batch_size:
                    lines = [",".join(header)] + [",".join(r) for r in batch]
                    data = parse_network_csv(lines)
                    await on_complete(process_network_data(data))
                    batch = []
            if batch:
                lines = [",".join(header)] + [",".join(r) for r in batch]
                data = parse_network_csv(lines)
                await on_complete(process_network_data(data))

        elif timeframe_seconds:
            current_batch = []
            start_ts = None

            for row in reader:
                row_dict = dict(zip(header, row))
                ts_str = row_dict.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    continue

                if start_ts is None:
                    start_ts = ts

                if (ts - start_ts).total_seconds() >= timeframe_seconds:
                    lines = [",".join(header)] + [",".join(r) for r in current_batch]
                    data = parse_network_csv(lines)
                    await on_complete(process_network_data(data))
                    current_batch = [row]
                    start_ts = ts
                else:
                    current_batch.append(row)

            if current_batch:
                lines = [",".join(header)] + [",".join(r) for r in current_batch]
                data = parse_network_csv(lines)
                await on_complete(process_network_data(data))


async def batch_csv_to_nl_async(
    file_path: str,
    batch_size: int,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Awaitable[Any]],
):
    """
    Async copy of batch processing that awaits the callback.
    """
    await _process_csv_file_async(file_path, on_complete, batch_size=batch_size)


async def batch_csv_to_nl_arr_async(
    file_path: str, batch_size: int
) -> List[Tuple[str, Tuple[int, int]]]:
    """
    Async copy of batch_csv_to_nl_arr that collects results from an async callback.
    """
    out: List[Tuple[str, Tuple[int, int]]] = []

    async def _collect(x: Tuple[str, Tuple[int, int]]) -> None:
        out.append(x)

    await batch_csv_to_nl_async(file_path, batch_size, _collect)
    return out


async def timeframe_csv_to_nl_async(
    file_path: str,
    timeframe_seconds: int,
    on_complete: Callable[[Tuple[str, Tuple[int, int]]], Awaitable[Any]],
):
    """
    Async copy of timeframe processing that awaits the callback.
    """
    await _process_csv_file_async(
        file_path, on_complete, timeframe_seconds=timeframe_seconds
    )


async def timeframe_csv_to_nl_arr_async(
    file_path: str, timeframe_seconds: int
) -> List[Tuple[str, Tuple[int, int]]]:
    """
    Async copy of timeframe_csv_to_nl_arr that collects results from an async callback.
    """
    out: List[Tuple[str, Tuple[int, int]]] = []

    async def _collect(x: Tuple[str, Tuple[int, int]]) -> None:
        out.append(x)

    await timeframe_csv_to_nl_async(file_path, timeframe_seconds, _collect)
    return out
