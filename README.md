# SIPFLOW

Browser-first SIP capture and call-flow viewer inspired by `sngrep`.

This first server-side MVP captures SIP packets locally and exposes them over a
small HTTP API plus Server-Sent Events.

## Run

```powershell
python -m sipflow.server
```

With dashboard/API login enabled:

```powershell
$env:SIPFLOW_AUTH_USER='admin'
$env:SIPFLOW_AUTH_PASSWORD='change-this-password'
python -m sipflow.server
```

When credentials are configured, SIPFLOW shows a login page at `/login` and
uses an HttpOnly session cookie after sign-in.

Open:

```text
http://127.0.0.1:8080
```

The browser UI includes capture controls, live call summaries, state filters,
a simple ladder view, raw SIP message inspection, and basic RTP media
diagnostics learned from SDP.

## Self-host With Docker

On a Linux host where SIP traffic is visible:

```sh
docker compose up -d --build
```

Set credentials before starting:

```sh
export SIPFLOW_AUTH_USER=admin
export SIPFLOW_AUTH_PASSWORD='change-this-password'
export SIPFLOW_PORT=9090
docker compose up -d --build
```

Open:

```text
http://SERVER_IP:9090
```

The Compose file uses:

- `network_mode: host` so the container can see the host network stack.
- `NET_RAW` and `NET_ADMIN` so raw packet capture can work.

If credentials are not provided, the Compose example defaults to
`admin` / `change-me`. Change this before exposing the dashboard on a network.

For a one-off Docker run:

```sh
docker build -t sipflow .
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  sipflow
```

Docker is best for Linux PBX/SBC/gateway hosts. Docker Desktop on Windows or
macOS usually captures inside the VM network, not the real host interface.

## Self-host With Installer

On a Linux host:

```sh
sudo ./install.sh
```

Requires Python 3.10 or newer. If multiple Python versions are installed, the
installer prefers `python3.13`, `python3.12`, `python3.11`, then `python3.10`.
You can force one with:

```sh
sudo SIPFLOW_PYTHON=/usr/bin/python3.11 ./install.sh
```

This installs SIPFLOW to `/opt/sipflow`, creates a `sipflow` system user, grants
raw packet capture capabilities to SIPFLOW's private Python venv, and starts a
systemd service. The installer prints the dashboard username and password when
it finishes.

To provide your own credentials:

```sh
sudo SIPFLOW_AUTH_USER=admin SIPFLOW_AUTH_PASSWORD='change-this-password' ./install.sh
```

Useful commands:

```sh
sudo systemctl status sipflow
sudo systemctl restart sipflow
sudo journalctl -u sipflow -f
```

## API

- `GET /api/interfaces` - list local IPv4 addresses that can be used for capture.
- `POST /api/capture/start` - start capture.
- `POST /api/capture/stop` - stop capture.
- `GET /api/capture/status` - capture status.
- `GET /api/calls` - current in-memory calls grouped by SIP `Call-ID`.
- `GET /api/events` - live Server-Sent Events stream.

Call records include a `media` object with SDP audio endpoints, observed RTP
streams, packet counts, codec, jitter estimate, packet-loss estimate, duration,
and warnings for one-way RTP, no RTP after answer, and private SDP IPs.

Audio playback is privacy-controlled and off by default. Enable `Record audio`
before starting capture to store browser-playable WAV audio for supported RTP
streams. SIPFLOW decodes `PCMA`, `PCMU`, and `L16` natively. Docker images also
include `ffmpeg` for common raw RTP codecs such as `G722`, `G729`, and `GSM`.
Encrypted SRTP and packetized codecs such as Opus are not decoded yet.

Example start request:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/capture/start `
  -ContentType 'application/json' `
  -Body '{"interface_ip":"192.168.1.10","ports":[5060]}'
```

To hide keepalive noise from the live stream and call list:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/capture/start `
  -ContentType 'application/json' `
  -Body '{"interface_ip":"192.168.1.10","ports":[5060],"ignore_methods":["OPTIONS"]}'
```

## Notes

On Windows, raw socket capture usually requires running the terminal as
Administrator. This MVP parses clear-text SIP over UDP and best-effort SIP over
TCP when a full SIP message is present in a captured segment. SIP over TLS is
encrypted and cannot be inspected here.

SIPFLOW must run on a machine that can actually see the SIP packets. Good
locations are the PBX host, SBC host, SIP proxy host, router/firewall host, or a
server connected to a SPAN/mirror port.
