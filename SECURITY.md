# Security Policy

SIPFLOW is an early self-hosted SIP/RTP troubleshooting dashboard. It can expose
sensitive SIP metadata and, when enabled, call audio. Treat deployments as
highly sensitive.

## Supported Versions

Security fixes are currently handled on the `main` branch only while the project
is in MVP stage.

## Deployment Guidance

- Do not expose SIPFLOW directly to the public internet.
- Prefer VPN, Tailscale, WireGuard, ZeroTier, or a private management network.
- If remote access is required, place SIPFLOW behind HTTPS and additional access
  control such as Cloudflare Access, Authelia, or an IP allowlist.
- Change default credentials before exposing the dashboard on any network.
- Keep audio recording disabled unless you have a specific troubleshooting need
  and legal consent to record.
- Run SIPFLOW only where packet visibility is intended, such as a PBX, SBC, SIP
  proxy, or SPAN/mirror-port capture host.

## Reporting Vulnerabilities

Please do not open public issues for sensitive vulnerabilities. Report privately
to the project maintainer through the repository's preferred private contact
method. If no private contact is listed yet, open a minimal public issue asking
for a private disclosure channel without including exploit details.

## Known MVP Limitations

- No built-in HTTPS.
- No rate limiting or brute-force protection.
- Single local username/password configuration.
- In-memory capture state.
- SIP TLS and SRTP contents are not decrypted.
- Audio recording may be legally regulated in your jurisdiction.
