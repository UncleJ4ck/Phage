# Phage: HTTP framing honor-matrix FRONT specs.
# License: Apache-2.0 License

"""One entry per reverse proxy UNDER TEST, as the FRONT half of a desync pair.

The back half asks "does this server honor a malformed Transfer-Encoding". The front
half asks the other question, which is what actually decides whether a pair is
exploitable: **does this proxy forward the malformed value at all**, and if so does it
still frame the message by Content-Length?

A pair desyncs when the front forwards a value it did not itself act on and the back
acts on it. Neither measurement alone predicts anything, which is the whole lesson of
the sozu finding: eight fronts looked clean against one strict back.

Each front proxies to `upstream_port`, where the harness runs a byte-recording origin.
Ports are bound to loopback only.
"""

# The origin the harness runs; fronts must forward here.
UPSTREAM_PORT = 9490

FRONTS = [
    {
        "name": "HAProxy 3.0",
        "image": "haproxytech/haproxy-alpine:3.0",
        "port": 9481,
        "config_path": "/usr/local/etc/haproxy/haproxy.cfg",
        "config": """global
    log stdout format raw local0 info
defaults
    mode http
    timeout connect 5s
    timeout client 10s
    timeout server 10s
frontend f
    bind 127.0.0.1:9481
    default_backend b
backend b
    server o 127.0.0.1:{up}
""",
    },
    {
        "name": "nginx 1.27",
        "image": "nginx:1.27",
        "port": 9482,
        "config_path": "/etc/nginx/nginx.conf",
        "config": """events {{}}
http {{
  server {{
    listen 127.0.0.1:9482;
    location / {{
      proxy_pass http://127.0.0.1:{up};
      proxy_http_version 1.1;
    }}
  }}
}}
""",
    },
    {
        "name": "Caddy 2",
        "image": "caddy:2",
        "port": 9483,
        "config_path": "/etc/caddy/Caddyfile",
        "config": """{{
  auto_https off
}}
:9483 {{
  reverse_proxy 127.0.0.1:{up}
}}
""",
    },
    {
        "name": "Traefik 3",
        "image": "traefik:v3.1",
        "port": 9484,
        "config_path": "/etc/traefik/traefik.yml",
        "config": """entryPoints:
  web:
    address: "127.0.0.1:9484"
providers:
  file:
    filename: /etc/traefik/traefik.yml
api:
  dashboard: false
log:
  level: ERROR
http:
  routers:
    r:
      rule: "PathPrefix(`/`)"
      service: s
      entryPoints: [web]
  services:
    s:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:{up}"
""",
    },
    {
        # POSITIVE CONTROL for this harness. sozu 2.1.0 is the known-vulnerable build
        # (kawa 0.6.8, CVE-class fixed in kawa 0.7.0 / sozu 2.2.0): it forwards a
        # malformed Transfer-Encoding alongside Content-Length. If this row does not come
        # back FORWARDS-BOTH on the whitespace variants, the instrument is broken and
        # every "safe" verdict above it is noise.
        "name": "sozu 2.1.0 (control, known-vulnerable)",
        "image": "clevercloud/sozu:2.1.0",
        "port": 9485,
        "boot": 120,
        "config_path": "/etc/sozu/sozu.toml",
        "args": ["start", "-c", "/etc/sozu/sozu.toml"],
        "config": """command_socket = "/tmp/sozu.sock"
log_level = "warn"
log_target = "stdout"
worker_count = 1
activate_listeners = true

[[listeners]]
protocol = "http"
address = "127.0.0.1:9485"

[clusters.C]
protocol = "http"
load_balancing = "ROUND_ROBIN"
frontends = [ {{ address = "127.0.0.1:9485", hostname = "lab" }} ]
backends = [ {{ address = "127.0.0.1:{up}", backend_id = "b1" }} ]
""",
    },
]
