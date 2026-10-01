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
    port: int
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
) -> CaptureSession:
    """Start a bounded tcpdump capture inside the container (non-blocking).

    The capture is started explicitly and confirmed alive; it is stopped
    explicitly by `stop_packet_capture`. There is no reliance on a timeout to
    end capture normally.
    """
    session = CaptureSession(
        container_name=container_name,
        pcap_path=f"/tmp/pq_capture_{int(time.time() * 1000)}.pcap",
        interface=interface,
        port=port,
    )
    if not _ensure_tcpdump(container_name):
        session.error = "tcpdump is not available in the container"
        return session

    try:
        session.proc = subprocess.Popen(
            ["docker", "exec", container_name, "tcpdump", "-i", interface,
             "-U", "-w", session.pcap_path, "-s", "0", f"port {port}"],
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
        bytes_received, bytes_sent, packets_received, packets_sent = _parse_pcap_file(
            host_pcap_path, session.port
        )
    except Exception as e:
        _cleanup_capture(session, host_pcap_path)
        return CaptureResult(
            meta=PcapMeta(), success=False, error=f"failed to parse pcap: {e}"
        )

    capture_duration = time.monotonic() - session.start_time
    _cleanup_capture(session, host_pcap_path)

    meta = PcapMeta(
        bytes_received=bytes_received,
        bytes_sent=bytes_sent,
        packets_received=packets_received,
        packets_sent=packets_sent,
        capture_duration=capture_duration,
        interface=session.interface,
        port=session.port,
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
