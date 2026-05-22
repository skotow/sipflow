import socket
import struct
import unittest

from sipflow.capture import PacketCapture, parse_ipv4_transport
from sipflow.rtp import parse_rtp_packet
from sipflow.sip import CallStore, parse_sip_message


class SipParsingTests(unittest.TestCase):
    def test_parse_invite(self) -> None:
        raw = (
            b"INVITE sip:1000@example.com SIP/2.0\r\n"
            b"Call-ID: abc123\r\n"
            b"From: <sip:100@example.com>;tag=a\r\n"
            b"To: <sip:1000@example.com>\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"User-Agent: test-agent\r\n"
            b"\r\n"
            b"v=0\r\n"
        )

        message = parse_sip_message(raw, "10.0.0.1:5060", "10.0.0.2:5060", "UDP")

        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message.method, "INVITE")
        self.assertEqual(message.call_id, "abc123")
        self.assertEqual(message.user_agent, "test-agent")
        self.assertEqual(message.body, "v=0\r\n")
        self.assertEqual(message.cseq_method, "INVITE")

    def test_call_summary_fields(self) -> None:
        store = CallStore()
        invite = parse_sip_message(
            (
                b"INVITE sip:1000@example.com SIP/2.0\r\n"
                b"Call-ID: abc123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>\r\n"
                b"CSeq: 1 INVITE\r\n\r\n"
            ),
            "10.0.0.1:5060",
            "10.0.0.2:5060",
            "UDP",
        )
        ok = parse_sip_message(
            (
                b"SIP/2.0 200 OK\r\n"
                b"Call-ID: abc123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>;tag=b\r\n"
                b"CSeq: 1 INVITE\r\n\r\n"
            ),
            "10.0.0.2:5060",
            "10.0.0.1:5060",
            "UDP",
        )

        assert invite is not None
        assert ok is not None
        store.add(invite)
        call = store.add(ok)

        self.assertIsNotNone(call)
        assert call is not None
        data = call.to_dict()
        self.assertEqual(data["initialMethod"], "INVITE")
        self.assertEqual(data["lastStatusCode"], 200)
        self.assertEqual(data["state"], "answered")

    def test_sdp_endpoints_and_rtp_stats(self) -> None:
        store = CallStore()
        invite = parse_sip_message(
            (
                b"INVITE sip:1000@example.com SIP/2.0\r\n"
                b"Call-ID: media123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>\r\n"
                b"CSeq: 1 INVITE\r\n"
                b"Content-Type: application/sdp\r\n"
                b"\r\n"
                b"v=0\r\n"
                b"c=IN IP4 10.0.0.1\r\n"
                b"m=audio 4000 RTP/AVP 8 0 101\r\n"
                b"a=rtpmap:8 PCMA/8000\r\n"
                b"a=rtpmap:0 PCMU/8000\r\n"
            ),
            "10.0.0.1:5060",
            "203.0.113.10:5060",
            "UDP",
        )
        ok = parse_sip_message(
            (
                b"SIP/2.0 200 OK\r\n"
                b"Call-ID: media123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>;tag=b\r\n"
                b"CSeq: 1 INVITE\r\n\r\n"
            ),
            "203.0.113.10:5060",
            "10.0.0.1:5060",
            "UDP",
        )

        assert invite is not None
        assert ok is not None
        store.add(invite)
        call = store.add(ok)
        rtp = parse_rtp_packet(build_rtp_packet(payload_type=8, sequence=1, timestamp=160), "10.0.0.1", 4000, "203.0.113.10", 12000)

        assert call is not None
        assert rtp is not None
        updated = store.add_rtp_packet(rtp)
        data = updated.to_dict() if updated else {}

        self.assertEqual(data["media"]["endpoints"][0]["key"], "10.0.0.1:4000")
        self.assertEqual(data["media"]["packetCount"], 1)
        self.assertEqual(data["media"]["streams"][0]["codec"], "PCMA/8000")

    def test_g711_audio_can_be_recorded_as_wav(self) -> None:
        store = CallStore()
        invite = parse_sip_message(
            (
                b"INVITE sip:1000@example.com SIP/2.0\r\n"
                b"Call-ID: audio123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>\r\n"
                b"CSeq: 1 INVITE\r\n"
                b"Content-Type: application/sdp\r\n\r\n"
                b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
            ),
            "10.0.0.1:5060",
            "203.0.113.10:5060",
            "UDP",
        )
        assert invite is not None
        store.add(invite)
        rtp = parse_rtp_packet(build_rtp_packet(payload_type=8, sequence=1, timestamp=160, payload=b"\xd5" * 160), "10.0.0.1", 4000, "203.0.113.10", 12000)

        assert rtp is not None
        call = store.add_rtp_packet(rtp)
        assert call is not None
        stream_id = next(iter(call.rtp_streams))
        audio = store.audio_wav("audio123", stream_id)

        self.assertIsNotNone(audio)
        assert audio is not None
        self.assertTrue(audio.startswith(b"RIFF"))
        self.assertIn(b"WAVE", audio[:16])

    def test_g722_stream_exposes_audio_url_for_ffmpeg_conversion(self) -> None:
        store = CallStore()
        invite = parse_sip_message(
            (
                b"INVITE sip:1000@example.com SIP/2.0\r\n"
                b"Call-ID: g722123\r\n"
                b"From: <sip:100@example.com>;tag=a\r\n"
                b"To: <sip:1000@example.com>\r\n"
                b"CSeq: 1 INVITE\r\n"
                b"Content-Type: application/sdp\r\n\r\n"
                b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 9\r\na=rtpmap:9 G722/8000\r\n"
            ),
            "10.0.0.1:5060",
            "203.0.113.10:5060",
            "UDP",
        )
        assert invite is not None
        store.add(invite)
        rtp = parse_rtp_packet(build_rtp_packet(payload_type=9, sequence=1, timestamp=160, payload=b"\x00" * 160), "10.0.0.1", 4000, "203.0.113.10", 12000)

        assert rtp is not None
        call = store.add_rtp_packet(rtp)
        assert call is not None
        stream = call.to_dict()["media"]["streams"][0]

        self.assertTrue(stream["audioRecorded"])
        self.assertTrue(stream["audioSupported"])
        self.assertIn("/api/audio?", stream["audioUrl"])

    def test_parse_udp_ipv4_payload(self) -> None:
        payload = b"OPTIONS sip:test SIP/2.0\r\nCall-ID: z\r\n\r\n"
        packet = build_ipv4_udp_packet("10.0.0.1", "10.0.0.2", 5060, 5080, payload)

        parsed = parse_ipv4_transport(packet)

        self.assertIsNotNone(parsed)
        assert parsed is not None
        src_ip, dst_ip, protocol, src_port, dst_port, parsed_payload = parsed
        self.assertEqual(src_ip, "10.0.0.1")
        self.assertEqual(dst_ip, "10.0.0.2")
        self.assertEqual(protocol, 17)
        self.assertEqual(src_port, 5060)
        self.assertEqual(dst_port, 5080)
        self.assertEqual(parsed_payload, payload)

    def test_capture_can_ignore_options(self) -> None:
        seen = []
        capture = PacketCapture(seen.append)
        payload = b"OPTIONS sip:test SIP/2.0\r\nCall-ID: z\r\nCSeq: 1 OPTIONS\r\n\r\n"
        packet = build_ipv4_udp_packet("10.0.0.1", "10.0.0.2", 5060, 5080, payload)

        capture._handle_ipv4_packet(packet, {5060}, {"OPTIONS"})

        self.assertEqual(seen, [])


def build_ipv4_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    return ip_header + udp_header + payload


def build_rtp_packet(payload_type: int, sequence: int, timestamp: int, payload: bytes | None = None) -> bytes:
    return struct.pack("!BBHII", 0x80, payload_type, sequence, timestamp, 1234) + (payload if payload is not None else b"\x00" * 160)


if __name__ == "__main__":
    unittest.main()
