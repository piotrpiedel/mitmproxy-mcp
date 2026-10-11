"""Password protection for the proxy when it listens beyond loopback.

mitmproxy's built-in `proxyauth` option challenges every client, local ones included, which
would break launch_chrome_with_proxy, browse_with_proxy and replays that reach the proxy over
127.0.0.1. This addon only challenges clients connecting from another machine.
"""

import base64
import binascii
import hmac
import ipaddress
import weakref

from mitmproxy import connection, http

AUTH_REJECTED_KEY = "lan_proxy_auth_rejected"
REALM = "mitmproxy-mcp"


def is_local_peer(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


class LanProxyAuth:
    """Requires HTTP Basic proxy credentials from clients that are not on this machine."""

    def __init__(self, username: str, password: str):
        self._expected = (username.encode(), password.encode())
        self._authenticated: "weakref.WeakSet[connection.Client]" = weakref.WeakSet()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        if self._is_exempt(flow):
            return
        if self._credentials_valid(flow):
            self._authenticated.add(flow.client_conn)
        else:
            self._reject(flow)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if self._is_exempt(flow) or flow.is_replay:
            return
        if flow.client_conn in self._authenticated:
            return
        if not self._credentials_valid(flow):
            self._reject(flow)

    def _is_exempt(self, flow: http.HTTPFlow) -> bool:
        peername = flow.client_conn.peername
        return bool(peername) and is_local_peer(peername[0])

    def _credentials_valid(self, flow: http.HTTPFlow) -> bool:
        header = flow.request.headers.get("Proxy-Authorization", "")
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            user, _, password = base64.b64decode(encoded.strip(), validate=True).partition(b":")
        except (binascii.Error, ValueError):
            return False
        # Non-short-circuiting so a wrong username takes as long as a wrong password.
        user_ok = hmac.compare_digest(user, self._expected[0])
        password_ok = hmac.compare_digest(password, self._expected[1])
        if user_ok and password_ok:
            del flow.request.headers["Proxy-Authorization"]
            return True
        return False

    def _reject(self, flow: http.HTTPFlow) -> None:
        flow.metadata[AUTH_REJECTED_KEY] = True
        flow.response = http.Response.make(
            407,
            "<html><body><h1>407 Proxy Authentication Required</h1></body></html>",
            {"Proxy-Authenticate": f'Basic realm="{REALM}"'},
        )
