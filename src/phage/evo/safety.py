# Phage: localhost-only scope guardrail.
# License: Apache-2.0 License

"""Refuse any target that is not loopback or an explicitly allowed lab host.
Authorized engagements only."""

import ipaddress
from typing import Iterable, Optional
from urllib.parse import urlparse

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "ip6-localhost"})


def _host_of(target: str) -> Optional[str]:
    ref = target if "://" in target else "//" + target
    try:
        return urlparse(ref, scheme="https").hostname
    except ValueError:
        # Malformed target (e.g. a broken IPv6 bracket) -> no host -> refuse.
        return None


def is_local_target(target: str, extra_allow: Iterable[str] = ()) -> bool:
    host = _host_of(target)
    if host is None:
        return False
    allow = set(extra_allow)
    if host in LOCAL_HOSTS or host in allow:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_local(target: str, extra_allow: Iterable[str] = ()) -> None:
    if not is_local_target(target, extra_allow):
        raise PermissionError(
            f"refusing non-lab target {target!r}: Phage is localhost-only. "
            f"Pass the host in extra_allow only for a lab box you own."
        )
