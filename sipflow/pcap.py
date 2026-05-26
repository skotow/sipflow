from __future__ import annotations

import gzip
import struct
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .capture import parse_ipv4_transport
from .rtp import RtpPacket, parse_rtp_packet
from .sip import SipMessage, parse_sip_message


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PCAPNG_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_SIMPLE_PACKET = 0x00000003
PCAPNG_ENHANCED_PACKET = 0x00000006
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
SUPPORTED_LINK_TYPES = {1, 101, 113, 276}


@dataclass
class PcapImportConfig:
    ports: set[int]
    ignore_methods: set[str]
    record_audio: bool = False


@dataclass
class PcapImportStats:
    packets: int = 0
    ipv4_packets: int = 0
    sip_messages: int = 0
    rtp_packets: int = 0
    unsupported_link_type: int | None = None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "packets": self.packets,
            "ipv4Packets": self.ipv4_packets,
            "sipMessages": self.sip_messages,
            "rtpPackets": self.rtp_packets,
            "unsupportedLinkType": self.unsupported_link_type,
        }


def import_pcap(
    data: bytes,
    config: PcapImportConfig,
    on_message: Callable[[SipMessage], None],
    on_rtp_packet: Callable[[RtpPacket], None] | None = None,
) -> PcapImportStats:
    data = decompress_capture_if_needed(data)

    if len(data) < 24:
        raise ValueError("PCAP file is too small")

    magic = data[:4]
    if struct.unpack("<I", magic)[0] == PCAPNG_SECTION_HEADER:
        return import_pcapng(data, config, on_message, on_rtp_packet)

    if magic not in PCAP_MAGICS:
        raise ValueError(
            "unsupported capture format; classic .pcap, .pcapng, or .pcap.gz is required "
            f"(first bytes: {data[:16].hex(' ')})"
        )

    endian, timestamp_scale = PCAP_MAGICS[magic]
    header = struct.unpack(f"{endian}HHIIII", data[4:24])
    network = header[5]
    stats = PcapImportStats()
    if network not in SUPPORTED_LINK_TYPES:
        stats.unsupported_link_type = network
        return stats

    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16
        if incl_len < 0 or offset + incl_len > len(data):
            break

        packet = data[offset : offset + incl_len]
        offset += incl_len
        stats.packets += 1
        timestamp = datetime.fromtimestamp(ts_sec + (ts_frac / timestamp_scale), timezone.utc).isoformat()
        ipv4 = extract_ipv4_packet(packet, network)
        if ipv4 is None:
            continue

        stats.ipv4_packets += 1
        process_ipv4_packet(ipv4, timestamp, config, on_message, on_rtp_packet, stats)

    return stats


def import_pcapng(
    data: bytes,
    config: PcapImportConfig,
    on_message: Callable[[SipMessage], None],
    on_rtp_packet: Callable[[RtpPacket], None] | None = None,
) -> PcapImportStats:
    stats = PcapImportStats()
    offset = 0
    endian = "<"
    interfaces: list[int] = []

    while offset + 12 <= len(data):
        raw_block_type = data[offset : offset + 4]
        if struct.unpack("<I", raw_block_type)[0] == PCAPNG_SECTION_HEADER:
            if offset + 16 > len(data):
                break
            bom_bytes = data[offset + 8 : offset + 12]
            bom_le = struct.unpack("<I", bom_bytes)[0]
            bom_be = struct.unpack(">I", bom_bytes)[0]
            if bom_le == PCAPNG_BYTE_ORDER_MAGIC:
                endian = "<"
            elif bom_be == PCAPNG_BYTE_ORDER_MAGIC:
                endian = ">"
            else:
                break
        block_type, block_len = struct.unpack(f"{endian}II", data[offset : offset + 8])

        if block_len < 12 or offset + block_len > len(data):
            break

        block = data[offset : offset + block_len]
        body = block[8:-4]

        if block_type == PCAPNG_SECTION_HEADER:
            interfaces = []
        elif block_type == PCAPNG_INTERFACE_DESCRIPTION:
            if len(body) >= 8:
                link_type = struct.unpack(f"{endian}H", body[:2])[0]
                interfaces.append(link_type)
                if link_type not in SUPPORTED_LINK_TYPES and stats.unsupported_link_type is None:
                    stats.unsupported_link_type = link_type
        elif block_type == PCAPNG_ENHANCED_PACKET:
            if len(body) >= 20:
                interface_id, ts_high, ts_low, captured_len, _packet_len = struct.unpack(f"{endian}IIIII", body[:20])
                packet = body[20 : 20 + captured_len]
                link_type = interfaces[interface_id] if interface_id < len(interfaces) else None
                timestamp_raw = (ts_high << 32) | ts_low
                timestamp = datetime.fromtimestamp(timestamp_raw / 1_000_000, timezone.utc).isoformat()
                process_pcap_frame(packet, link_type, timestamp, config, on_message, on_rtp_packet, stats)
        elif block_type == PCAPNG_SIMPLE_PACKET:
            if len(body) >= 4 and interfaces:
                packet_len = struct.unpack(f"{endian}I", body[:4])[0]
                packet = body[4 : 4 + min(packet_len, len(body) - 4)]
                timestamp = datetime.now(timezone.utc).isoformat()
                process_pcap_frame(packet, interfaces[0], timestamp, config, on_message, on_rtp_packet, stats)

        offset += block_len

    return stats


def process_pcap_frame(
    packet: bytes,
    network: int | None,
    timestamp: str,
    config: PcapImportConfig,
    on_message: Callable[[SipMessage], None],
    on_rtp_packet: Callable[[RtpPacket], None] | None,
    stats: PcapImportStats,
) -> None:
    if network is None:
        return

    stats.packets += 1
    ipv4 = extract_ipv4_packet(packet, network)
    if ipv4 is None:
        return

    stats.ipv4_packets += 1
    process_ipv4_packet(ipv4, timestamp, config, on_message, on_rtp_packet, stats)


def extract_ipv4_packet(packet: bytes, network: int) -> bytes | None:
    if network == 101:
        return packet if packet and packet[0] >> 4 == 4 else None

    if network == 113:
        if len(packet) < 16:
            return None
        protocol_type = struct.unpack("!H", packet[14:16])[0]
        payload = packet[16:]
        return payload if protocol_type == 0x0800 and payload and payload[0] >> 4 == 4 else None

    if network == 276:
        if len(packet) < 20:
            return None
        protocol_type = struct.unpack("!H", packet[0:2])[0]
        payload = packet[20:]
        return payload if protocol_type == 0x0800 and payload and payload[0] >> 4 == 4 else None

    if network != 1 or len(packet) < 14:
        return None

    ether_type_offset = 12
    ether_type = struct.unpack("!H", packet[ether_type_offset : ether_type_offset + 2])[0]
    payload_offset = 14
    while ether_type in {0x8100, 0x88A8} and len(packet) >= payload_offset + 4:
        ether_type = struct.unpack("!H", packet[payload_offset + 2 : payload_offset + 4])[0]
        payload_offset += 4

    if ether_type != 0x0800:
        return None
    payload = packet[payload_offset:]
    return payload if payload and payload[0] >> 4 == 4 else None


def decompress_capture_if_needed(data: bytes) -> bytes:
    if not data.startswith(b"\x1f\x8b"):
        return data

    try:
        return gzip.decompress(data)
    except (OSError, EOFError):
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        recovered = decompressor.decompress(data)
        if recovered:
            return recovered
        raise ValueError("unable to decompress gzip capture; file appears truncated or corrupt")


def process_ipv4_packet(
    packet: bytes,
    timestamp: str,
    config: PcapImportConfig,
    on_message: Callable[[SipMessage], None],
    on_rtp_packet: Callable[[RtpPacket], None] | None,
    stats: PcapImportStats,
) -> None:
    parsed = parse_ipv4_transport(packet)
    if parsed is None:
        return

    src_ip, dst_ip, protocol, src_port, dst_port, payload = parsed
    if protocol == 17 and on_rtp_packet:
        rtp = parse_rtp_packet(payload, src_ip, src_port, dst_ip, dst_port, timestamp)
        if rtp:
            if not config.record_audio:
                rtp.payload = b""
            on_rtp_packet(rtp)
            stats.rtp_packets += 1

    if src_port not in config.ports and dst_port not in config.ports:
        return

    transport = "UDP" if protocol == 17 else "TCP"
    sip = parse_sip_message(
        payload,
        src=f"{src_ip}:{src_port}",
        dst=f"{dst_ip}:{dst_port}",
        transport=transport,
        timestamp=timestamp,
    )
    if not sip:
        return

    cseq_method = sip.cseq_method or ""
    message_method = sip.method or cseq_method
    if config.ignore_methods and message_method.upper() in config.ignore_methods:
        return

    on_message(sip)
    stats.sip_messages += 1
