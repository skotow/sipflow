from __future__ import annotations

import socket
import struct
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .rtp import RtpPacket, parse_rtp_packet
from .sip import SipMessage, parse_sip_message


SIO_RCVALL = 0x98000001
RCVALL_ON = 1
RCVALL_OFF = 0


@dataclass
class Interface:
    name: str
    ip: str


@dataclass
class CaptureConfig:
    interface_ip: str
    ports: list[int]
    ignore_methods: set[str] = field(default_factory=set)
    record_audio: bool = False


class PacketCapture:
    def __init__(
        self,
        on_message: Callable[[SipMessage], None],
        on_rtp_packet: Callable[[RtpPacket], None] | None = None,
    ) -> None:
        self._on_message = on_message
        self._on_rtp_packet = on_rtp_packet
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._status = "stopped"
        self._error: str | None = None

    def start(self, config: CaptureConfig) -> None:
        if self.running:
            raise RuntimeError("capture is already running")
        if not config.ports:
            raise ValueError("at least one SIP port is required")

        self._stop_event.clear()
        self._ready_event.clear()
        self._error = None
        self._status = "starting"
        self._thread = threading.Thread(target=self._run, args=(config,), daemon=True)
        self._thread.start()
        self._ready_event.wait(timeout=1)
        if self._status == "error":
            raise RuntimeError(self._error or "capture failed to start")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._status = "stopped"

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, str | bool | None]:
        return {"running": self.running, "status": self._status, "error": self._error}

    def _run(self, config: CaptureConfig) -> None:
        try:
            if sys.platform == "win32":
                self._run_windows(config)
            else:
                self._run_packet_socket(config)
        except Exception as exc:
            self._error = str(exc)
            self._status = "error"
            self._ready_event.set()
        finally:
            if self._status != "error":
                self._status = "stopped"

    def _run_windows(self, config: CaptureConfig) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((config.interface_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(SIO_RCVALL, RCVALL_ON)
        sock.settimeout(0.5)
        self._status = "running"
        self._ready_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    packet = sock.recvfrom(65535)[0]
                except socket.timeout:
                    continue
                self._handle_ipv4_packet(packet, set(config.ports), config.ignore_methods, config.record_audio)
        finally:
            try:
                sock.ioctl(SIO_RCVALL, RCVALL_OFF)
            finally:
                sock.close()

    def _run_packet_socket(self, config: CaptureConfig) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise RuntimeError("raw packet capture is not supported on this platform")

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.settimeout(0.5)
        self._status = "running"
        self._ready_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    frame = sock.recvfrom(65535)[0]
                except socket.timeout:
                    continue
                if len(frame) < 14:
                    continue
                ether_type = struct.unpack("!H", frame[12:14])[0]
                if ether_type == 0x0800:
                    self._handle_ipv4_packet(frame[14:], set(config.ports), config.ignore_methods, config.record_audio)
        finally:
            sock.close()

    def _handle_ipv4_packet(
        self,
        packet: bytes,
        ports: set[int],
        ignore_methods: set[str] | None = None,
        record_audio: bool = False,
    ) -> None:
        parsed = parse_ipv4_transport(packet)
        if parsed is None:
            return

        src_ip, dst_ip, protocol, src_port, dst_port, payload = parsed
        timestamp = datetime.now(timezone.utc).isoformat()
        if protocol == 17 and self._on_rtp_packet:
            rtp = parse_rtp_packet(payload, src_ip, src_port, dst_ip, dst_port, timestamp)
            if rtp:
                if not record_audio:
                    rtp.payload = b""
                self._on_rtp_packet(rtp)

        if src_port not in ports and dst_port not in ports:
            return

        transport = "UDP" if protocol == 17 else "TCP"
        sip = parse_sip_message(
            payload,
            src=f"{src_ip}:{src_port}",
            dst=f"{dst_ip}:{dst_port}",
            transport=transport,
            timestamp=timestamp,
        )
        if sip:
            cseq_method = sip.cseq_method or ""
            message_method = sip.method or cseq_method
            if ignore_methods and message_method.upper() in ignore_methods:
                return
            self._on_message(sip)


def list_interfaces() -> list[Interface]:
    hostname = socket.gethostname()
    addresses: set[str] = set()

    try:
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(item[4][0])
    except socket.gaierror:
        pass

    try:
        addresses.add(socket.gethostbyname(hostname))
    except socket.gaierror:
        pass

    addresses.discard("127.0.0.1")
    interfaces = [Interface(name=ip, ip=ip) for ip in sorted(addresses)]
    interfaces.append(Interface(name="loopback", ip="127.0.0.1"))
    return interfaces


def parse_ipv4_transport(packet: bytes) -> tuple[str, str, int, int, int, bytes] | None:
    if len(packet) < 20:
        return None

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(packet) < ihl:
        return None

    protocol = packet[9]
    if protocol not in {6, 17}:
        return None

    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])

    if protocol == 17:
        if len(packet) < ihl + 8:
            return None
        src_port, dst_port, length = struct.unpack("!HHH", packet[ihl : ihl + 6])
        payload = packet[ihl + 8 : ihl + length]
        return src_ip, dst_ip, protocol, src_port, dst_port, payload

    if len(packet) < ihl + 20:
        return None
    src_port, dst_port = struct.unpack("!HH", packet[ihl : ihl + 4])
    data_offset = (packet[ihl + 12] >> 4) * 4
    if data_offset < 20:
        return None
    payload = packet[ihl + data_offset :]
    return src_ip, dst_ip, protocol, src_port, dst_port, payload
