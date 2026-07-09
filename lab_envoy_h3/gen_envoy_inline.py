"""Envoy's QUIC transport socket rejects filename-based private keys with
"Failed to load incomplete private key" (v1.31); inline_string works. This reads the
secret-free envoy.yaml template plus the local self-signed lab.crt/lab.key and writes
envoy.local.yaml with the cert/key embedded inline. envoy.local.yaml is gitignored
(it carries the key). Run before `docker compose up`. Regenerate after new certs."""

CRT = open("lab.crt").read()
KEY = open("lab.key").read()


def inline(pem):
    return '"' + pem.replace("\n", "\\n") + '"'


tmpl = open("envoy.yaml").read()
old = """              tls_certificates:
              - certificate_chain: { filename: /certs/lab.crt }
                private_key: { filename: /certs/lab.key }"""
new = (
    "              tls_certificates:\n"
    "              - certificate_chain: { inline_string: %s }\n"
    "                private_key: { inline_string: %s }" % (inline(CRT), inline(KEY))
)
assert old in tmpl, "template anchor not found in envoy.yaml"
open("envoy.local.yaml", "w").write(tmpl.replace(old, new))
print("wrote envoy.local.yaml (inline cert/key)")
