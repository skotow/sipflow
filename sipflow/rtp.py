from __future__ import annotations

import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
import wave


STATIC_PAYLOADS = {
    0: ("PCMU", 8000),
    3: ("GSM", 8000),
    8: ("PCMA", 8000),
    9: ("G722", 8000),
    18: ("G729", 8000),
}

FFMPEG_CODECS = {
    "G722": ("g722", 16000),
    "G729": ("g729", 8000),
    "GSM": ("gsm", 8000),
}


@dataclass
class RtpPacket:
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload_type: int
    sequence: int
    rtp_timestamp: int
    ssrc: int
    payload_size: int
    payload: bytes = b""

    @property
    def src(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"


def parse_rtp_packet(
    payload: bytes,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    timestamp: str | None = None,
) -> RtpPacket | None:
    if len(payload) < 12:
        return None
    if payload[0] >> 6 != 2:
        return None

    payload_type = payload[1] & 0x7F
    if 72 <= payload_type <= 76:
        return None

    csrc_count = payload[0] & 0x0F
    header_len = 12 + csrc_count * 4
    if len(payload) < header_len:
        return None

    sequence, rtp_timestamp, ssrc = struct.unpack("!HII", payload[2:12])
    media_payload = payload[header_len:]
    return RtpPacket(
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload_type=payload_type,
        sequence=sequence,
        rtp_timestamp=rtp_timestamp,
        ssrc=ssrc,
        payload_size=len(media_payload),
        payload=media_payload,
    )


def decode_native_payload(codec: str | None, payload: bytes) -> bytes:
    if not codec:
        return b""
    codec_name = codec.split("/", 1)[0].upper()
    if codec_name == "PCMA":
        return b"".join(_linear_to_bytes(decode_alaw(sample)) for sample in payload)
    if codec_name == "PCMU":
        return b"".join(_linear_to_bytes(decode_ulaw(sample)) for sample in payload)
    if codec_name == "L16":
        return decode_l16(payload)
    return b""


def can_decode_audio(codec: str | None) -> bool:
    codec_name = codec_base_name(codec)
    return codec_name in {"PCMA", "PCMU", "L16"} or codec_name in FFMPEG_CODECS


def codec_base_name(codec: str | None) -> str:
    return (codec or "").split("/", 1)[0].upper()


def ffmpeg_wav_bytes(codec: str | None, payload: bytes) -> bytes | None:
    codec_name = codec_base_name(codec)
    codec_config = FFMPEG_CODECS.get(codec_name)
    if not codec_config or not payload:
        return None

    input_format, sample_rate = codec_config
    command = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        input_format,
        "-i",
        "pipe:0",
        "-ac",
        "1",
        "-ar",
        str(sample_rate),
        "-f",
        "wav",
        "pipe:1",
    ]
    try:
        result = subprocess.run(
            command,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0 or not result.stdout.startswith(b"RIFF"):
        return None
    return result.stdout


def wav_bytes(pcm: bytes, sample_rate: int = 8000) -> bytes:
    output = BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(pcm)
    return output.getvalue()


def decode_l16(payload: bytes) -> bytes:
    if len(payload) < 2:
        return b""
    if len(payload) % 2:
        payload = payload[:-1]
    samples = struct.unpack(f"!{len(payload) // 2}h", payload)
    return b"".join(_linear_to_bytes(sample) for sample in samples)


def decode_ulaw(value: int) -> int:
    value = ~value & 0xFF
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    sample = ((mantissa << 3) + 0x84) << exponent
    sample -= 0x84
    return -sample if sign else sample


def decode_alaw(value: int) -> int:
    value ^= 0x55
    sign = value & 0x80
    exponent = (value >> 4) & 0x07
    mantissa = value & 0x0F
    if exponent == 0:
        sample = (mantissa << 4) + 8
    else:
        sample = ((mantissa << 4) + 0x108) << (exponent - 1)
    return sample if sign else -sample


def _linear_to_bytes(sample: int) -> bytes:
    sample = max(-32768, min(32767, sample))
    return struct.pack("<h", sample)
