# Phage: HTTP/2 front specs for the downgrade half.
# License: Apache-2.0 License

"""The same reverse proxies, configured to speak HTTP/2 cleartext (h2c) to the client.

The HTTP/1 front half asks which malformed `Transfer-Encoding` a proxy forwards. This
half asks a question HTTP/1 cannot: HTTP/2 has no `Transfer-Encoding`, and RFC 9113
section 8.2.2 forbids connection-specific header fields on the wire, so a proxy that
carries one down to an HTTP/1 origin has minted a framing header the client was never
allowed to send. That is the H2.TE downgrade, and nothing in `fronts.py` can see it.

Only h2c is used, no TLS. A front that cannot serve h2c is reported unreachable rather
than guessed at; that is a limit of the harness and it is recorded as one.

Ports and the upstream match `fronts.py`, so the two halves never run at the same time.
"""

from fronts import UPSTREAM_PORT  # noqa: F401  (re-exported for the runner)

FRONTS_H2 = [
    {
        "name": "HAProxy 3.2",
        "id": "haproxy",
        "image": "haproxytech/haproxy-alpine:3.2",
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
    bind 127.0.0.1:9481 proto h2
    default_backend b
backend b
    server o 127.0.0.1:{up}
""",
    },
    {
        "name": "nginx 1.31",
        "id": "nginx",
        "image": "nginx:1.31",
        "port": 9482,
        "config_path": "/etc/nginx/nginx.conf",
        "config": """events {{}}
http {{
  server {{
    listen 127.0.0.1:9482;
    http2 on;
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
        "id": "caddy",
        "image": "caddy:2",
        "port": 9483,
        "config_path": "/etc/caddy/Caddyfile",
        "config": """{{
  auto_https off
  servers {{
    protocols h1 h2c
  }}
}}
:9483 {{
  reverse_proxy 127.0.0.1:{up}
}}
""",
    },
    {
        "name": "Apache httpd 2.4",
        "id": "httpd",
        "image": "httpd:2.4",
        "port": 9486,
        "config_path": "/usr/local/apache2/conf/httpd.conf",
        "config": """ServerName lab
Listen 127.0.0.1:9486
LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule authz_core_module modules/mod_authz_core.so
LoadModule unixd_module modules/mod_unixd.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule http2_module modules/mod_http2.so
Protocols h2c http/1.1
ErrorLog /dev/null
ProxyPass / http://127.0.0.1:{up}/
ProxyPassReverse / http://127.0.0.1:{up}/
""",
    },
    {
        "name": "Envoy 1.39",
        "id": "envoy",
        "image": "envoyproxy/envoy:v1.39-latest",
        "port": 9487,
        "config_path": "/etc/envoy/envoy.yaml",
        "args": ["-c", "/etc/envoy/envoy.yaml", "-l", "error"],
        "config": """static_resources:
  listeners:
  - address: {{ socket_address: {{ address: 127.0.0.1, port_value: 9487 }} }}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: e
          codec_type: HTTP2
          route_config:
            virtual_hosts:
            - name: a
              domains: ["*"]
              routes: [ {{ match: {{ prefix: "/" }}, route: {{ cluster: c }} }} ]
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {{ "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }}
  clusters:
  - name: c
    load_assignment:
      cluster_name: c
      endpoints:
      - lb_endpoints:
        - endpoint: {{ address: {{ socket_address: {{ address: 127.0.0.1, port_value: {up} }} }} }}
""",
    },
]
