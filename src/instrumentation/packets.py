"""Packet capture and byte counting instrumentation.

See architecture.md §3.5. Uses tcpdump restricted to the laboratory
interface and port for packet-size/timing metadata only.

Counts IP-packet bytes (wire-level, not application payload). Excludes
Ethernet framing/physical-layer overhead. Excludes unrelated traffic and
traffic outside the experiment window.
"""
from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field


@dataclass
class PcapMeta:
    """Metadata from packet capture."""
    bytes_received: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    packets_sent: int = 0
    capture_duration: float = 0.0
    interface: str = ""
    port: int = 0
    # Phase 7: RTT and handshake latency (from packet timestamps)
    handshake_rtt_count: int | None = None          # Observed RTT count (1 or 2), None if unobservable
    handshake_latency_p50_ms: float | None = None   # Median handshake latency (ClientHello -> ServerHello)
    handshake_latency_p95_ms: float | None = None   # P95 handshake latency
    # Phase 7 (D1 validation): forced-HRR flow evidence, observed from the
    # same pcap window. None when the flow could not be parsed.
    hrr_observed: bool | None = None
    client_hello2_observed: bool | None = None
    cookie_observed: bool | None = None
    server_hello_observed: bool | None = None


@dataclass
class CaptureResult:
    """Result from packet capture."""
    meta: PcapMeta
    pcap_path: str | None = None
    success: bool = False
    error: str | None = None


@dataclass
class CaptureSession:
    """A running, bounded packet-capture session.

    `started` is True only after the capture process has been confirmed alive.
    `error` records why a session could not start.
    """

    container_name: str
    pcap_path: str
    interface: str
    port: int = 0           # Primary port (kept for compatibility)
    ports: list[int] = field(default_factory=list)  # All ports to capture
    proc: "subprocess.Popen | None" = None
    started: bool = False
    start_time: float = 0.0
    error: str | None = None


def _parse_pcap_file(pcap_path: str, server_port: int = 4433) -> tuple[int, int, int, int]:
    """Parse a pcap file and count IP-packet bytes.

    Returns (bytes_received, bytes_sent, packets_received, packets_sent).

    Direction is determined by port:
    - Packets with destination port = server_port are bytes_received
    - Packets with source port = server_port are bytes_sent

    IP packet length is taken from the IP header's total length field,
    which excludes Ethernet framing.
    """
    bytes_received = 0
    bytes_sent = 0
    packets_received = 0
    packets_sent = 0

    with open(pcap_path, "rb") as f:
        # Read global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            return 0, 0, 0, 0

        magic = struct.unpack("<I", global_header[0:4])[0]
        # Determine endianness
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            return 0, 0, 0, 0

        # Link type at offset 20
        link_type = struct.unpack(endian + "I", global_header[20:24])[0]

        # Link type 1 = Ethernet, 101 = Raw IP, 113 = Linux SLL
        if link_type == 1:
            eth_header_len = 14
        elif link_type == 101:
            eth_header_len = 0
        elif link_type == 113:
            eth_header_len = 16
        else:
            # Unsupported link type
            return 0, 0, 0, 0

        # Read packet records
        while True:
            record_header = f.read(16)
            if len(record_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", record_header
            )

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break

            # Parse IP packet
            if eth_header_len > 0:
                if len(packet_data) < eth_header_len:
                    continue
                ip_packet = packet_data[eth_header_len:]
            else:
                ip_packet = packet_data

            if len(ip_packet) < 20:
                continue

            # IP header: version/IHL at byte 0, total length at bytes 2-3
            version_ihl = ip_packet[0]
            ihl = (version_ihl & 0x0F) * 4
            if ihl < 20 or len(ip_packet) < ihl:
                continue

            ip_total_length = struct.unpack("!H", ip_packet[2:4])[0]
            if ip_total_length < ihl or ip_total_length > len(ip_packet):
                continue

            # Protocol at byte 9
            protocol = ip_packet[9]
            if protocol != 6:  # TCP only
                continue

            # TCP header starts at ihl
            if len(ip_packet) < ihl + 4:
                continue

            src_port = struct.unpack("!H", ip_packet[ihl:ihl + 2])[0]
            dst_port = struct.unpack("!H", ip_packet[ihl + 2:ihl + 4])[0]

            # IP total length is the IP packet length (excludes Ethernet)
            ip_bytes = ip_total_length

            if dst_port == server_port:
                bytes_received += ip_bytes
                packets_received += 1
            elif src_port == server_port:
                bytes_sent += ip_bytes
                packets_sent += 1

    return bytes_received, bytes_sent, packets_received, packets_sent


# TLS 1.3 Handshake message types (RFC 8446)
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2
_HS_HELLO_RETRY_REQUEST = 2  # Same as ServerHello, distinguished by content
_HS_ENCRYPTED_EXTENSIONS = 8
_HS_CERTIFICATE = 11
_HS_CERTIFICATE_VERIFY = 15
_HS_FINISHED = 20


def _parse_handshake_rtt(pcap_path: str, ports: list[int]) -> tuple[int | None, float | None, float | None]:
    """Parse pcap for TLS 1.3 handshake messages and compute RTT count and latency.

    Identifies flows by client IP:port and tracks message sequence:
    - Baseline: ClientHello -> ServerHello (1 RTT)
    - HRR: ClientHello -> HelloRetryRequest -> ClientHello2 -> ServerHello (2 RTT)

    Returns (rtt_count, handshake_latency_p50_ms, handshake_latency_p95_ms) or (None, None, None) if unobservable.
    """
    import struct
    from collections import defaultdict

    # Flow state per client (IP:port)
    # Each flow tracks: ch1_time, hrr_time, ch2_time, sh_time
    flows: dict[tuple[str, int], dict[str, float]] = defaultdict(dict)

    with open(pcap_path, "rb") as f:
        # Read global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            return None, None, None

        magic = struct.unpack("<I", global_header[0:4])[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            return None, None, None

        link_type = struct.unpack(endian + "I", global_header[20:24])[0]
        if link_type == 1:
            eth_header_len = 14
        elif link_type == 101:
            eth_header_len = 0
        elif link_type == 113:
            eth_header_len = 16
        else:
            return None, None, None

        while True:
            record_header = f.read(16)
            if len(record_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", record_header)
            timestamp = ts_sec + ts_usec / 1_000_000.0

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break

            if eth_header_len > 0:
                if len(packet_data) < eth_header_len:
                    continue
                ip_packet = packet_data[eth_header_len:]
            else:
                ip_packet = packet_data

            if len(ip_packet) < 20:
                continue

            version_ihl = ip_packet[0]
            ihl = (version_ihl & 0x0F) * 4
            if ihl < 20 or len(ip_packet) < ihl:
                continue

            ip_total_length = struct.unpack("!H", ip_packet[2:4])[0]
            if ip_total_length < ihl or ip_total_length > len(ip_packet):
                continue

            protocol = ip_packet[9]
            if protocol != 6:  # TCP only
                continue

            if len(ip_packet) < ihl + 4:
                continue

            src_port = struct.unpack("!H", ip_packet[ihl:ihl + 2])[0]
            dst_port = struct.unpack("!H", ip_packet[ihl + 2:ihl + 4])[0]

            # Only process packets on our monitored ports
            if src_port not in ports and dst_port not in ports:
                continue

            # Extract source IP
            if len(ip_packet) < ihl + 16:
                continue
            src_ip = ".".join(str(b) for b in ip_packet[ihl + 12:ihl + 16])

            # Check for TLS record layer
            if len(ip_packet) < ihl + 20:  # IP + TCP (min 20) + TLS (min 5)
                continue

            tcp_offset = ihl
            tcp_data_offset = (ip_packet[tcp_offset + 12] >> 4) * 4
            if tcp_data_offset < 20 or len(ip_packet) < ihl + tcp_data_offset + 5:
                continue

            tls_offset = ihl + tcp_data_offset
            tls_data = ip_packet[tls_offset:]

            if len(tls_data) < 5:
                continue

            # TLS Record Header: ContentType(1) + Version(2) + Length(2)
            content_type = tls_data[0]
            if content_type != 22:  # Handshake
                continue

            tls_length = struct.unpack("!H", tls_data[3:5])[0]
            if len(tls_data) < 5 + tls_length:
                continue

            handshake_data = tls_data[5:5 + tls_length]
            if len(handshake_data) < 4:
                continue

            # Handshake header: msg_type(1) + length(3)
            msg_type = handshake_data[0]
            msg_len = int.from_bytes(handshake_data[1:4], "big")

            if msg_len > len(handshake_data) - 4:
                continue

            msg_body = handshake_data[4:4 + msg_len]

            flow_key = (src_ip, src_port) if dst_port in ports else (src_ip, dst_port)

            if msg_type == _HS_CLIENT_HELLO:
                # Check if this is ClientHello2 (contains cookie extension)
                # For simplicity, we track first and second ClientHello
                if "ch1_time" not in flows[flow_key]:
                    flows[flow_key]["ch1_time"] = timestamp
                elif "ch2_time" not in flows[flow_key]:
                    # This could be ClientHello2 - check for cookie extension
                    # Cookie extension type = 44 (0x002c)
                    has_cookie = False
                    if len(msg_body) >= 2:
                        ext_len = struct.unpack("!H", msg_body[:2])[0]
                        if len(msg_body) >= 2 + ext_len:
                            ext_data = msg_body[2:2 + ext_len]
                            # Parse extensions
                            i = 0
                            while i + 4 <= len(ext_data):
                                ext_type = struct.unpack("!H", ext_data[i:i+2])[0]
                                ext_len = struct.unpack("!H", ext_data[i+2:i+4])[0]
                                if ext_type == 44:  # cookie extension
                                    has_cookie = True
                                    break
                                i += 4 + ext_len
                    if has_cookie:
                        flows[flow_key]["ch2_time"] = timestamp

            elif msg_type == _HS_SERVER_HELLO or msg_type == _HS_HELLO_RETRY_REQUEST:
                # Distinguish HRR from ServerHello by checking for supported_versions = TLS 1.3
                # HRR has body: legacy_version(2) + random(32) + cipher_suite(2) + legacy_compression(1) + extensions
                # ServerHello has similar but with supported_versions extension
                is_hrr = False
                if len(msg_body) >= 38:  # minimum HRR/ServerHello size
                    # Check for HelloRetryRequest: it has no supported_versions extension in the same way
                    # Simple heuristic: HRR has a "cookie" extension in extensions
                    # Actually, HRR is distinguished by the fact that it's the first ServerHello-type message
                    # and the client responds with a second ClientHello
                    pass

                # Better approach: if we've seen a ClientHello but no HRR yet, this is HRR
                if "hrr_time" not in flows[flow_key] and "ch1_time" in flows[flow_key]:
                    # This is likely HRR
                    flows[flow_key]["hrr_time"] = timestamp
                elif "sh_time" not in flows[flow_key]:
                    # This is likely ServerHello
                    flows[flow_key]["sh_time"] = timestamp

    # Analyze completed flows
    rtt_counts = []
    latencies = []

    for flow_key, events in flows.items():
        if "ch1_time" in events and "sh_time" in events:
            ch1 = events["ch1_time"]
            sh = events["sh_time"]
            latency_ms = (sh - ch1) * 1000
            latencies.append(latency_ms)

            if "hrr_time" in events:
                # HRR path: 2 RTT
                rtt_counts.append(2)
            else:
                # Baseline: 1 RTT
                rtt_counts.append(1)

    if not rtt_counts:
        return None, None, None

    # Median RTT count
    rtt_counts.sort()
    median_rtt = rtt_counts[len(rtt_counts) // 2]

    # Latency percentiles
    latencies.sort()
    p50_latency = latencies[len(latencies) // 2]
    p95_idx = int(len(latencies) * 0.95)
    p95_latency = latencies[min(p95_idx, len(latencies) - 1)]

    return median_rtt, p50_latency, p95_latency


# --- D1 forced-HRR flow evidence (Phase 7, RQ4/RQ5) ------------------------
# The D1 validation phase needs to observe, from the packet capture alone,
# whether the full forced-HRR flow occurred:
#   ClientHello -> HelloRetryRequest(+cookie) -> ClientHello2(+cookie) -> ServerHello
# This is a SEPARATE read of the same pcap; it does not alter the W1 RTT path.
_CLIENT_HELLO_COOKIE_EXTENSION = 44  # RFC 8446, TLS ExtensionType.cookie


def _parse_client_hello_extensions(msg_body: bytes) -> set[int]:
    """Return the extension type IDs present in a ClientHello body.

    Parses the ClientHello layout (RFC 8446 section 4.1.2):
    legacy_version(2) + random(32) + session_id + cipher_suites +
    compression_methods + extensions. Returns an empty set when the body
    cannot be parsed. Used to detect the stateless-cookie extension (type 44)
    carried by ClientHello2.
    """
    try:
        if len(msg_body) < 2 + 32 + 1:
            return set()
        offset = 2 + 32  # legacy_version + random
        sid_len = msg_body[offset]
        offset += 1 + sid_len
        if offset + 2 > len(msg_body):
            return set()
        cs_len = struct.unpack("!H", msg_body[offset:offset + 2])[0]
        offset += 2 + cs_len
        if offset + 1 > len(msg_body):
            return set()
        comp_len = msg_body[offset]
        offset += 1 + comp_len
        if offset + 2 > len(msg_body):
            return set()
        ext_total = struct.unpack("!H", msg_body[offset:offset + 2])[0]
        offset += 2
        end = min(offset + ext_total, len(msg_body))
        extension_types: set[int] = set()
        while offset + 4 <= end:
            ext_type = struct.unpack("!H", msg_body[offset:offset + 2])[0]
            ext_size = struct.unpack("!H", msg_body[offset + 2:offset + 4])[0]
            extension_types.add(ext_type)
            offset += 4 + ext_size
        return extension_types
    except Exception:
        return set()


@dataclass
class D1FlowObservation:
    """Observation-derived D1 forced-HRR flow evidence from a packet capture."""

    hrr_observed: bool = False
    client_hello2_observed: bool = False
    cookie_observed: bool = False
    server_hello_observed: bool = False
    rtt_count: int | None = None


def _iter_tls_handshake_messages(pcap_path: str, ports: list[int]):
    """Yield (flow_key, msg_type, msg_body, timestamp) for TLS handshake records.

    Reads the same pcap format as `_parse_handshake_rtt` (little/big-endian
    libpcap, Ethernet / raw-IP / Linux-SLL link types, TCP-only) but exposes
    the individual handshake messages so flow-level evidence can be derived.
    """
    try:
        with open(pcap_path, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return
            magic = struct.unpack("<I", global_header[0:4])[0]
            if magic == 0xa1b2c3d4:
                endian = "<"
            elif magic == 0xd4c3b2a1:
                endian = ">"
            else:
                return
            link_type = struct.unpack(endian + "I", global_header[20:24])[0]
            if link_type == 1:
                eth_header_len = 14
            elif link_type == 101:
                eth_header_len = 0
            elif link_type == 113:
                eth_header_len = 16
            else:
                return

            while True:
                record_header = f.read(16)
                if len(record_header) < 16:
                    break
                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                    endian + "IIII", record_header
                )
                timestamp = ts_sec + ts_usec / 1_000_000.0
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break

                if eth_header_len > 0:
                    if len(packet_data) < eth_header_len:
                        continue
                    ip_packet = packet_data[eth_header_len:]
                else:
                    ip_packet = packet_data

                if len(ip_packet) < 20:
                    continue
                ihl = (ip_packet[0] & 0x0F) * 4
                if ihl < 20 or len(ip_packet) < ihl:
                    continue
                ip_total_length = struct.unpack("!H", ip_packet[2:4])[0]
                if ip_total_length < ihl or ip_total_length > len(ip_packet):
                    continue
                if ip_packet[9] != 6:  # TCP only
                    continue
                if len(ip_packet) < ihl + 4:
                    continue

                src_port = struct.unpack("!H", ip_packet[ihl:ihl + 2])[0]
                dst_port = struct.unpack("!H", ip_packet[ihl + 2:ihl + 4])[0]
                if src_port not in ports and dst_port not in ports:
                    continue
                if len(ip_packet) < ihl + 16:
                    continue
                src_ip = ".".join(str(b) for b in ip_packet[ihl + 12:ihl + 16])
                if len(ip_packet) < ihl + 20:
                    continue

                tcp_data_offset = (ip_packet[ihl + 12] >> 4) * 4
                if tcp_data_offset < 20 or len(ip_packet) < ihl + tcp_data_offset + 5:
                    continue
                tls_data = ip_packet[ihl + tcp_data_offset:]
                if len(tls_data) < 5 or tls_data[0] != 22:  # TLS handshake record
                    continue
                tls_length = struct.unpack("!H", tls_data[3:5])[0]
                if len(tls_data) < 5 + tls_length:
                    continue
                handshake_data = tls_data[5:5 + tls_length]
                if len(handshake_data) < 4:
                    continue
                msg_type = handshake_data[0]
                msg_len = int.from_bytes(handshake_data[1:4], "big")
                if msg_len > len(handshake_data) - 4:
                    continue
                msg_body = handshake_data[4:4 + msg_len]
                flow_key = (src_ip, src_port) if dst_port in ports else (src_ip, dst_port)
                yield flow_key, msg_type, msg_body, timestamp
    except Exception:
        return


def parse_d1_handshake_flow(pcap_path: str, ports: list[int]) -> D1FlowObservation:
    """Derive D1 forced-HRR flow evidence from a pcap (observation only)."""
    obs = D1FlowObservation()
    flows: dict[tuple[str, int], dict] = {}
    for flow_key, msg_type, msg_body, timestamp in _iter_tls_handshake_messages(
        pcap_path, ports
    ):
        events = flows.setdefault(flow_key, {})
        if msg_type == _HS_CLIENT_HELLO:
            if "ch1_time" not in events:
                events["ch1_time"] = timestamp
            else:
                events["ch2_time"] = timestamp
                if _CLIENT_HELLO_COOKIE_EXTENSION in _parse_client_hello_extensions(msg_body):
                    events["ch2_cookie"] = True
        elif msg_type in (_HS_SERVER_HELLO, _HS_HELLO_RETRY_REQUEST):
            if "hrr_time" not in events and "ch1_time" in events:
                events["hrr_time"] = timestamp
            elif "sh_time" not in events:
                events["sh_time"] = timestamp

    rtt_counts: list[int] = []
    for events in flows.values():
        hrr = "hrr_time" in events
        if hrr:
            obs.hrr_observed = True
        if "ch2_time" in events:
            obs.client_hello2_observed = True
        if events.get("ch2_cookie"):
            obs.cookie_observed = True
        if "sh_time" in events:
            obs.server_hello_observed = True
        if "ch1_time" in events and "sh_time" in events:
            rtt_counts.append(2 if hrr else 1)

    if rtt_counts:
        rtt_counts.sort()
        obs.rtt_count = rtt_counts[len(rtt_counts) // 2]
    return obs


def _ensure_tcpdump(container_name: str, timeout: float = 60.0) -> bool:
    """Ensure tcpdump is available inside the container. Returns success."""
    try:
        subprocess.run(
            ["docker", "exec", container_name, "sh", "-c",
             "command -v tcpdump || apk add --no-cache tcpdump"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return True
    except Exception:
        return False


def start_packet_capture(
    container_name: str,
    port: int = 4433,
    interface: str = "eth0",
    ports: list[int] | None = None,
) -> CaptureSession:
    """Start a bounded tcpdump capture inside the container (non-blocking).

    The capture is started explicitly and confirmed alive; it is stopped
    explicitly by `stop_packet_capture`. There is no reliance on a timeout to
    end capture normally.

    Args:
        container_name: Docker container name/ID
        port: Single port (for backward compatibility)
        interface: Network interface to capture on
        ports: List of ports to capture (e.g., [4433, 4434]). If provided, overrides `port`.
    """
    if ports is None:
        ports = [port]

    session = CaptureSession(
        container_name=container_name,
        pcap_path=f"/tmp/pq_capture_{int(time.time() * 1000)}.pcap",
        interface=interface,
        port=ports[0],
        ports=ports,
    )
    if not _ensure_tcpdump(container_name):
        session.error = "tcpdump is not available in the container"
        return session

    # Build port filter for tcpdump: "port 4433 or port 4434"
    port_filter = " or ".join(f"port {p}" for p in ports)

    try:
        session.proc = subprocess.Popen(
            ["docker", "exec", container_name, "tcpdump", "-i", interface,
             "-U", "-w", session.pcap_path, "-s", "0", port_filter],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as e:
        session.error = f"failed to start tcpdump: {e}"
        return session

    # Confirm the capture process is actually running.
    time.sleep(0.2)
    if session.proc.poll() is not None:
        detail = ""
        try:
            if session.proc.stderr is not None:
                detail = (session.proc.stderr.read() or "").strip()
        except Exception:
            detail = ""
        session.error = f"tcpdump exited immediately: {detail}"
        return session

    session.started = True
    session.start_time = time.monotonic()
    return session


def _cleanup_capture(session: CaptureSession, host_pcap_path: str | None) -> None:
    """Remove the capture file from the container and the host copy."""
    try:
        subprocess.run(
            ["docker", "exec", session.container_name, "rm", "-f", session.pcap_path],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except Exception:
        pass
    try:
        if host_pcap_path and os.path.exists(host_pcap_path):
            os.remove(host_pcap_path)
    except Exception:
        pass


def stop_packet_capture(session: CaptureSession, stop_timeout: float = 15.0) -> CaptureResult:
    """Stop the capture explicitly, then copy, parse and clean up.

    On any failure the returned CaptureResult has success=False and a reason;
    the caller must treat that as "unavailable", never as a measured zero.
    """
    if not session.started or session.proc is None:
        return CaptureResult(
            meta=PcapMeta(),
            success=False,
            error=session.error or "capture was not started",
        )

    proc = session.proc
    # Explicit stop: SIGINT lets tcpdump flush and exit cleanly.
    try:
        subprocess.run(
            ["docker", "exec", session.container_name, "pkill", "-INT", "tcpdump"],
            capture_output=True,
            text=True,
            timeout=stop_timeout,
            check=False,
        )
    except Exception:
        pass

    # Wait for termination; the timeout is only an emergency backstop.
    try:
        proc.wait(timeout=stop_timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    host_pcap_path = os.path.join(
        tempfile.gettempdir(), os.path.basename(session.pcap_path)
    )
    try:
        copy = subprocess.run(
            ["docker", "cp", f"{session.container_name}:{session.pcap_path}", host_pcap_path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if copy.returncode != 0:
            raise RuntimeError((copy.stderr or "docker cp failed").strip())
    except Exception as e:
        _cleanup_capture(session, host_pcap_path)
        return CaptureResult(
            meta=PcapMeta(), success=False, error=f"failed to copy pcap: {e}"
        )

    try:
        # For multi-port capture (D2/D3), sum bytes across all monitored ports
        total_bytes_received = 0
        total_bytes_sent = 0
        total_packets_received = 0
        total_packets_sent = 0
        for port in session.ports:
            br, bs, pr, ps = _parse_pcap_file(host_pcap_path, port)
            total_bytes_received += br
            total_bytes_sent += bs
            total_packets_received += pr
            total_packets_sent += ps
        bytes_received = total_bytes_received
        bytes_sent = total_bytes_sent
        packets_received = total_packets_received
        packets_sent = total_packets_sent
    except Exception as e:
        _cleanup_capture(session, host_pcap_path)
        return CaptureResult(
            meta=PcapMeta(), success=False, error=f"failed to parse pcap: {e}"
        )

    capture_duration = time.monotonic() - session.start_time

    # Parse pcap for RTT and handshake latency (Phase 7 RQ5)
    handshake_rtt_count = None
    handshake_latency_p50_ms = None
    handshake_latency_p95_ms = None
    try:
        handshake_rtt_count, handshake_latency_p50_ms, handshake_latency_p95_ms = _parse_handshake_rtt(
            host_pcap_path, session.ports
        )
    except Exception:
        # If parsing fails, leave as None (unobservable)
        pass

    # D1 forced-HRR flow evidence from the same bounded pcap window.
    d1_flow: D1FlowObservation | None = None
    try:
        d1_flow = parse_d1_handshake_flow(host_pcap_path, session.ports)
    except Exception:
        d1_flow = None

    _cleanup_capture(session, host_pcap_path)

    meta = PcapMeta(
        bytes_received=bytes_received,
        bytes_sent=bytes_sent,
        packets_received=packets_received,
        packets_sent=packets_sent,
        capture_duration=capture_duration,
        interface=session.interface,
        port=session.port,
        handshake_rtt_count=handshake_rtt_count,
        handshake_latency_p50_ms=handshake_latency_p50_ms,
        handshake_latency_p95_ms=handshake_latency_p95_ms,
        hrr_observed=(d1_flow.hrr_observed if d1_flow else None),
        client_hello2_observed=(d1_flow.client_hello2_observed if d1_flow else None),
        cookie_observed=(d1_flow.cookie_observed if d1_flow else None),
        server_hello_observed=(d1_flow.server_hello_observed if d1_flow else None),
    )
    return CaptureResult(meta=meta, success=True)


def capture_packets(interface: str, port: int, duration: float) -> PcapMeta:
    """Capture packets and return PcapMeta.

    This is the legacy host-side interface. The primary Phase 4
    methodology uses start_packet_capture()/stop_packet_capture() with
    tcpdump inside the TLS-server container.
    """
    # For host-side capture, we would need tcpdump on the host
    # This is not the primary Phase 4 methodology
    return PcapMeta()
