from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote as url_quote

from .rtp import RtpPacket, STATIC_PAYLOADS, can_decode_audio, decode_native_payload, ffmpeg_wav_bytes, wav_bytes


SIP_METHODS = {
    "ACK",
    "BYE",
    "CANCEL",
    "INFO",
    "INVITE",
    "MESSAGE",
    "NOTIFY",
    "OPTIONS",
    "PRACK",
    "PUBLISH",
    "REFER",
    "REGISTER",
    "SUBSCRIBE",
    "UPDATE",
}


@dataclass
class MediaEndpoint:
    ip: str
    port: int
    codecs: dict[int, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "key": self.key,
            "codecs": {str(payload_type): codec for payload_type, codec in sorted(self.codecs.items())},
            "isPrivateIp": is_private_ip(self.ip),
        }


@dataclass
class RtpStreamStats:
    src: str
    dst: str
    payload_type: int
    codec: str | None
    first_seen_at: str
    last_seen_at: str
    packet_count: int = 0
    payload_bytes: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    expected_packets: int = 0
    jitter: float = 0.0
    _last_arrival: datetime | None = None
    _last_rtp_timestamp: int | None = None
    _clock_rate: int = 8000
    recorded_pcm: bytearray = field(default_factory=bytearray)
    recorded_payload: bytearray = field(default_factory=bytearray)
    audio_recorded: bool = False

    def add(self, packet: RtpPacket, codec: str | None, clock_rate: int) -> None:
        self.last_seen_at = packet.timestamp
        self.packet_count += 1
        self.payload_bytes += packet.payload_size
        self.codec = self.codec or codec
        self._clock_rate = clock_rate

        if self.first_sequence is None:
            self.first_sequence = packet.sequence
            self.last_sequence = packet.sequence
            self.expected_packets = 1
        elif self.last_sequence is not None:
            delta = (packet.sequence - self.last_sequence) % 65536
            if 0 < delta < 3000:
                self.expected_packets += delta
                self.last_sequence = packet.sequence

        arrival = parse_iso(packet.timestamp)
        if arrival and self._last_arrival and self._last_rtp_timestamp is not None:
            arrival_delta = (arrival - self._last_arrival).total_seconds()
            rtp_delta = ((packet.rtp_timestamp - self._last_rtp_timestamp) & 0xFFFFFFFF) / max(clock_rate, 1)
            transit_delta = abs(arrival_delta - rtp_delta)
            self.jitter += (transit_delta - self.jitter) / 16

        if arrival:
            self._last_arrival = arrival
        self._last_rtp_timestamp = packet.rtp_timestamp
        if packet.payload:
            self.recorded_payload.extend(packet.payload)
            decoded = decode_native_payload(codec, packet.payload)
            if decoded:
                self.recorded_pcm.extend(decoded)
                self.audio_recorded = True

    def to_dict(self, stream_id: str | None = None, call_id: str | None = None) -> dict[str, Any]:
        lost = max(self.expected_packets - self.packet_count, 0)
        duration = duration_seconds(self.first_seen_at, self.last_seen_at)
        audio_url = None
        audio_supported = can_decode_audio(self.codec)
        if self.has_audio_payload() and audio_supported and stream_id and call_id:
            audio_url = f"/api/audio?call_id={url_quote(call_id)}&stream_id={url_quote(stream_id)}"
        audio_note = None
        if self.recorded_payload and not audio_supported:
            audio_note = f"Audio playback unavailable for {self.codec or 'unknown codec'}."
        elif self.recorded_payload and audio_supported and not audio_url:
            audio_note = "Audio payload recorded."
        return {
            "id": stream_id,
            "src": self.src,
            "dst": self.dst,
            "payloadType": self.payload_type,
            "codec": self.codec,
            "firstSeenAt": self.first_seen_at,
            "lastSeenAt": self.last_seen_at,
            "durationSeconds": duration,
            "packetCount": self.packet_count,
            "payloadBytes": self.payload_bytes,
            "expectedPackets": self.expected_packets,
            "lostPackets": lost,
            "lossPercent": round((lost / self.expected_packets) * 100, 2) if self.expected_packets else 0,
            "jitterMs": round(self.jitter * 1000, 2),
            "audioRecorded": self.has_audio_payload(),
            "audioSupported": audio_supported,
            "audioUrl": audio_url,
            "audioNote": audio_note,
        }

    def audio_wav(self) -> bytes | None:
        if self.recorded_pcm:
            return wav_bytes(bytes(self.recorded_pcm), self._clock_rate)
        if self.recorded_payload:
            return ffmpeg_wav_bytes(self.codec, bytes(self.recorded_payload))
        return None

    def has_audio_payload(self) -> bool:
        return bool(self.recorded_pcm or self.recorded_payload)


@dataclass
class SipMessage:
    timestamp: str
    src: str
    dst: str
    transport: str
    start_line: str
    method: str | None
    status_code: int | None
    reason: str | None
    call_id: str | None
    from_header: str | None
    to_header: str | None
    cseq: str | None
    user_agent: str | None
    content_type: str | None
    headers: dict[str, str]
    body: str
    raw: str

    @property
    def cseq_method(self) -> str | None:
        if not self.cseq:
            return None
        parts = self.cseq.split()
        if len(parts) < 2:
            return None
        return parts[-1].upper()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "transport": self.transport,
            "startLine": self.start_line,
            "method": self.method,
            "statusCode": self.status_code,
            "reason": self.reason,
            "callId": self.call_id,
            "from": self.from_header,
            "to": self.to_header,
            "cseq": self.cseq,
            "cseqMethod": self.cseq_method,
            "userAgent": self.user_agent,
            "contentType": self.content_type,
            "headers": self.headers,
            "body": self.body,
            "raw": self.raw,
        }


@dataclass
class Call:
    id: str
    started_at: str
    last_seen_at: str
    state: str = "unknown"
    participants: set[str] = field(default_factory=set)
    messages: list[SipMessage] = field(default_factory=list)
    media_endpoints: dict[str, MediaEndpoint] = field(default_factory=dict)
    rtp_streams: dict[str, RtpStreamStats] = field(default_factory=dict)
    answered_at: str | None = None

    def add(self, message: SipMessage) -> None:
        self.messages.append(message)
        self.last_seen_at = message.timestamp
        self.participants.add(message.src)
        self.participants.add(message.dst)
        self.state = derive_state(self.state, message)
        if message.status_code and 200 <= message.status_code < 300 and message.cseq_method == "INVITE":
            self.answered_at = self.answered_at or message.timestamp
        for endpoint in parse_sdp_audio_endpoints(message.body, message.content_type):
            existing = self.media_endpoints.get(endpoint.key)
            if existing:
                existing.codecs.update(endpoint.codecs)
            else:
                self.media_endpoints[endpoint.key] = endpoint

    def add_rtp_packet(self, packet: RtpPacket) -> None:
        payload_codec, clock_rate = self.codec_for_payload_type(packet.payload_type)
        key = f"{packet.src}>{packet.dst}:{packet.ssrc}"
        stream = self.rtp_streams.get(key)
        if stream is None:
            stream = RtpStreamStats(
                src=packet.src,
                dst=packet.dst,
                payload_type=packet.payload_type,
                codec=payload_codec,
                first_seen_at=packet.timestamp,
                last_seen_at=packet.timestamp,
            )
            self.rtp_streams[key] = stream
        stream.add(packet, payload_codec, clock_rate)

    def codec_for_payload_type(self, payload_type: int) -> tuple[str | None, int]:
        for endpoint in self.media_endpoints.values():
            codec = endpoint.codecs.get(payload_type)
            if codec:
                return codec, codec_clock_rate(codec)
        static = STATIC_PAYLOADS.get(payload_type)
        if static:
            return static
        return None, 8000

    def media_summary(self) -> dict[str, Any]:
        streams = [stream.to_dict(stream_id, self.id) for stream_id, stream in self.rtp_streams.items()]
        diagnostics = media_diagnostics(self, streams)
        return {
            "endpoints": [endpoint.to_dict() for endpoint in self.media_endpoints.values()],
            "streams": streams,
            "rtpFlowing": bool(streams),
            "streamCount": len(streams),
            "packetCount": sum(stream["packetCount"] for stream in streams),
            "codecs": sorted({stream["codec"] for stream in streams if stream["codec"]} | {
                codec for endpoint in self.media_endpoints.values() for codec in endpoint.codecs.values()
            }),
            "diagnostics": diagnostics,
        }

    def to_dict(self) -> dict[str, Any]:
        first_message = self.messages[0] if self.messages else None
        last_message = self.messages[-1] if self.messages else None
        return {
            "id": self.id,
            "startedAt": self.started_at,
            "lastSeenAt": self.last_seen_at,
            "state": self.state,
            "initialMethod": first_request_method(self.messages),
            "caller": first_message.from_header if first_message else None,
            "callee": first_message.to_header if first_message else None,
            "lastStatusCode": last_status_code(self.messages),
            "lastSummary": message_summary(last_message) if last_message else None,
            "answeredAt": self.answered_at,
            "participants": sorted(self.participants),
            "messageCount": len(self.messages),
            "media": self.media_summary(),
            "messages": [message.to_dict() for message in self.messages],
        }

    def audio_wav(self, stream_id: str) -> bytes | None:
        stream = self.rtp_streams.get(stream_id)
        if not stream:
            return None
        return stream.audio_wav()


class CallStore:
    def __init__(self) -> None:
        self._calls: dict[str, Call] = {}

    def add(self, message: SipMessage) -> Call | None:
        if not message.call_id:
            return None

        call = self._calls.get(message.call_id)
        if call is None:
            call = Call(
                id=message.call_id,
                started_at=message.timestamp,
                last_seen_at=message.timestamp,
            )
            self._calls[message.call_id] = call

        call.add(message)
        return call

    def add_rtp_packet(self, packet: RtpPacket) -> Call | None:
        for call in self._calls.values():
            if packet.src in call.media_endpoints or packet.dst in call.media_endpoints:
                call.add_rtp_packet(packet)
                return call
        return None

    def clear(self) -> None:
        self._calls.clear()

    def get(self, call_id: str) -> Call | None:
        return self._calls.get(call_id)

    def audio_wav(self, call_id: str, stream_id: str) -> bytes | None:
        call = self.get(call_id)
        if not call:
            return None
        return call.audio_wav(stream_id)

    def list(self) -> list[dict[str, Any]]:
        return [call.to_dict() for call in sorted(self._calls.values(), key=lambda item: item.last_seen_at, reverse=True)]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_sip_message(payload: bytes, src: str, dst: str, transport: str, timestamp: str | None = None) -> SipMessage | None:
    text = payload.decode("utf-8", errors="replace").strip("\x00")
    if not looks_like_sip(text):
        return None

    header_text, separator, body = text.partition("\r\n\r\n")
    if not separator:
        header_text, separator, body = text.partition("\n\n")

    lines = [line.rstrip("\r") for line in header_text.splitlines() if line.strip()]
    if not lines:
        return None

    start_line = lines[0]
    headers = parse_headers(lines[1:])
    method = None
    status_code = None
    reason = None

    if start_line.startswith("SIP/2.0"):
        parts = start_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        if len(parts) >= 3:
            reason = parts[2]
    else:
        first = start_line.split(" ", 1)[0].upper()
        if first in SIP_METHODS:
            method = first

    return SipMessage(
        timestamp=timestamp or now_iso(),
        src=src,
        dst=dst,
        transport=transport,
        start_line=start_line,
        method=method,
        status_code=status_code,
        reason=reason,
        call_id=get_header(headers, "call-id", "i"),
        from_header=get_header(headers, "from", "f"),
        to_header=get_header(headers, "to", "t"),
        cseq=get_header(headers, "cseq"),
        user_agent=get_header(headers, "user-agent", "server"),
        content_type=get_header(headers, "content-type", "c"),
        headers=headers,
        body=body,
        raw=text,
    )


def looks_like_sip(text: str) -> bool:
    if text.startswith("SIP/2.0"):
        return True

    first = text.split(" ", 1)[0].upper()
    return first in SIP_METHODS and "SIP/2.0" in text[:256]


def parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    current_name: str | None = None

    for line in lines:
        if line.startswith((" ", "\t")) and current_name:
            headers[current_name] = f"{headers[current_name]} {line.strip()}"
            continue

        name, separator, value = line.partition(":")
        if not separator:
            continue

        current_name = name.strip().lower()
        headers[current_name] = value.strip()

    return headers


def get_header(headers: dict[str, str], *names: str) -> str | None:
    for name in names:
        value = headers.get(name.lower())
        if value:
            return value
    return None


def derive_state(current: str, message: SipMessage) -> str:
    if message.method == "OPTIONS":
        return "keepalive"
    if message.method == "REGISTER":
        return "registration"
    if message.method == "INVITE":
        return "calling"
    if message.status_code in {180, 183}:
        return "ringing"
    if message.status_code and 200 <= message.status_code < 300:
        if "INVITE" in (message.cseq or "").upper():
            return "answered"
        if "REGISTER" in (message.cseq or "").upper():
            return "registered"
        if "OPTIONS" in (message.cseq or "").upper():
            return "keepalive"
        return current
    if message.method == "ACK" and current == "answered":
        return "confirmed"
    if message.method == "BYE":
        return "completed"
    if message.method == "CANCEL":
        return "canceled"
    if message.status_code and message.status_code >= 400:
        return "failed"
    return current


def first_request_method(messages: list[SipMessage]) -> str | None:
    for message in messages:
        if message.method:
            return message.method
        if message.cseq_method:
            return message.cseq_method
    return None


def last_status_code(messages: list[SipMessage]) -> int | None:
    for message in reversed(messages):
        if message.status_code:
            return message.status_code
    return None


def message_summary(message: SipMessage) -> str:
    if message.method:
        return message.method
    if message.status_code:
        cseq_method = f" {message.cseq_method}" if message.cseq_method else ""
        reason = f" {message.reason}" if message.reason else ""
        return f"{message.status_code}{reason}{cseq_method}"
    return message.start_line


def parse_sdp_audio_endpoints(body: str, content_type: str | None) -> list[MediaEndpoint]:
    if not body:
        return []
    if content_type and "sdp" not in content_type.lower():
        return []

    session_ip: str | None = None
    current_ip: str | None = None
    current_port: int | None = None
    current_payloads: list[int] = []
    codecs: dict[int, str] = {}
    endpoints: list[MediaEndpoint] = []

    def flush() -> None:
        if current_port and (current_ip or session_ip):
            endpoint_codecs = {payload_type: codecs.get(payload_type, STATIC_PAYLOADS.get(payload_type, (str(payload_type), 8000))[0]) for payload_type in current_payloads}
            endpoints.append(MediaEndpoint(ip=current_ip or session_ip or "", port=current_port, codecs=endpoint_codecs))

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith("c=IN IP4 "):
            ip = line.split()[-1]
            if current_port:
                current_ip = ip
            else:
                session_ip = ip
        elif line.startswith("m="):
            flush()
            current_ip = None
            current_port = None
            current_payloads = []
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "m=audio":
                try:
                    current_port = int(parts[1])
                    current_payloads = [int(item) for item in parts[3:] if item.isdigit()]
                except ValueError:
                    current_port = None
                    current_payloads = []
        elif line.startswith("a=rtpmap:"):
            payload, _, codec_value = line[9:].partition(" ")
            if payload.isdigit() and codec_value:
                codecs[int(payload)] = codec_value.strip().upper()

    flush()
    return [endpoint for endpoint in endpoints if endpoint.ip and endpoint.port > 0]


def media_diagnostics(call: Call, streams: list[dict[str, Any]]) -> list[dict[str, str]]:
    diagnostics: list[dict[str, str]] = []
    if call.answered_at and call.media_endpoints and not streams:
        diagnostics.append({"level": "warning", "code": "no_rtp_after_answer", "message": "No RTP seen after the call was answered."})

    directions = {(stream["src"], stream["dst"]) for stream in streams}
    if len(directions) == 1 and call.answered_at:
        diagnostics.append({"level": "warning", "code": "one_way_rtp", "message": "RTP is flowing in one direction only."})

    public_signaling = any(not is_private_ip(part.split(":", 1)[0]) for part in call.participants)
    private_media = [endpoint.key for endpoint in call.media_endpoints.values() if is_private_ip(endpoint.ip)]
    if public_signaling and private_media:
        diagnostics.append({"level": "warning", "code": "private_sdp_ip", "message": f"Private media IP advertised in SDP: {', '.join(private_media)}"})

    return diagnostics


def is_private_ip(value: str) -> bool:
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def duration_seconds(start: str, end: str) -> float:
    parsed_start = parse_iso(start)
    parsed_end = parse_iso(end)
    if not parsed_start or not parsed_end:
        return 0
    return round(max(0, (parsed_end - parsed_start).total_seconds()), 3)


def codec_clock_rate(codec: str) -> int:
    parts = codec.split("/")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 8000
