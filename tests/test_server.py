import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sipflow.server import create_server


class AuthTests(unittest.TestCase):
    def test_dashboard_uses_login_session_when_configured(self) -> None:
        server = create_server("127.0.0.1", 0, "admin", "secret")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            base_url = f"http://127.0.0.1:{server.server_address[1]}"
            url = f"{base_url}/"
            login_page = urlopen(url, timeout=2)

            self.assertEqual(login_page.status, 200)
            self.assertIn(b"Sign in to view live SIP traffic", login_page.read())

            with self.assertRaises(HTTPError) as raised:
                urlopen(f"{base_url}/api/calls", timeout=2)

            self.assertEqual(raised.exception.code, 401)
            raised.exception.close()

            request = Request(
                f"{base_url}/api/login",
                data=json.dumps({"username": "admin", "password": "secret"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            login_response = urlopen(request, timeout=2)
            cookie = login_response.headers["Set-Cookie"].split(";", 1)[0]

            response = urlopen(Request(url, headers={"Cookie": cookie}), timeout=2)

            self.assertEqual(response.status, 200)
            self.assertIn(b"SIPFLOW", response.read())
        finally:
            server.shutdown()
            server.server_close()


class RtpPublishTests(unittest.TestCase):
    def test_rtp_publish_is_throttled_per_call(self) -> None:
        server = create_server("127.0.0.1", 0)
        state = server.RequestHandlerClass.state
        call_id = "abc123"

        try:
            self.assertTrue(state.should_publish_rtp(call_id))
            self.assertFalse(state.should_publish_rtp(call_id))
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
