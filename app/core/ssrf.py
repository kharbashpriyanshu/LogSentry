"""SSRF (Server-Side Request Forgery) Defense Validator.

Validates destination URLs before outbound HTTP dispatch, neutralizing attacks against:
  - Loopback interfaces (127.0.0.1, ::1, localhost)
  - Private RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Cloud instance metadata services (169.254.169.254, fd00:ec2::254)
  - Link-local and multicast ranges (169.254.0.0/16, 224.0.0.0/4)
  - DNS rebinding to internal networks
"""

import ipaddress
import socket
from urllib.parse import urlparse

# Explicitly forbidden hostnames
_FORBIDDEN_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "metadata",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
    }
)


def validate_outbound_url(url: str) -> str:
    """
    Validates that a URL is safe for outbound dispatch and does not target
    internal, private, loopback, or cloud-provider metadata infrastructure.

    Raises:
      ValueError: if URL uses an unsupported scheme, forbidden host, or resolves to private IP.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted."
        )

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("URL must specify a valid hostname.")

    if hostname in _FORBIDDEN_HOSTNAMES or hostname.endswith((".local", ".internal", ".localhost")):
        raise ValueError(f"SSRF Protection: Hostname '{hostname}' is not permitted.")

    # Resolve hostname to verify destination IP addresses
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname '{hostname}': {e}")

    for family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid resolved IP address '{ip_str}'")

        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                f"SSRF Protection: Destination '{hostname}' resolves to private/internal IP '{ip_str}'."
            )

        # Explicit check for AWS/GCP/Azure link-local metadata IP
        if ip_str == "169.254.169.254":
            raise ValueError("SSRF Protection: Access to cloud metadata service is strictly blocked.")

    return url.strip()
