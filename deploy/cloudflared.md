# Cloudflare Tunnel in front of VCM

Cloudflare Tunnel publishes the app without opening inbound ports. The real
client IP arrives in the `CF-Connecting-IP` header.

## 1. Run the tunnel as a sidecar (`deploy/cloudflared.yml`)

```yaml
# docker compose -f docker-compose.yml -f deploy/cloudflared.yml up -d
services:
  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: "${CLOUDFLARE_TUNNEL_TOKEN}"
  vcm:
    environment:
      VCM_RP_ID: "vcm.example.com"
      VCM_RP_ORIGIN: "https://vcm.example.com"
      VCM_COOKIE_SECURE: "true"
      # cloudflared connects from within the compose network:
      VCM_TRUSTED_PROXIES: "172.16.0.0/12"
      VCM_REAL_IP_HEADERS: "cf-connecting-ip"
```

In the Cloudflare Zero Trust dashboard, point the tunnel's public hostname
`vcm.example.com` → `http://vcm:8000`.

## 2. Why the trusted-proxy setting matters

VCM only honours `CF-Connecting-IP` when the **direct** TCP peer is in
`VCM_TRUSTED_PROXIES`. Because cloudflared is the only thing that can reach the
app (no published ports), a client cannot spoof the header to bypass the
source-IP allowlist. Keep `ports:` closed on the `vcm` service.

## 3. Defense in depth

Also add a Cloudflare Access policy (email/OTP/SSO) and/or WAF IP rules — the
app's own IP allowlist (`/admin`) is the last line, not the only one.
