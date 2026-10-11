from mitmproxy import http
from typing import Iterable, List
from ..models import ScopeConfig
from .auth import AUTH_REJECTED_KEY


def host_in_scope(host: str, domains: Iterable[str]) -> bool:
    """True when host is one of the domains or a subdomain of one.

    Matching is case-insensitive and whole-label: "example.com" covers
    "api.example.com" but not "notexample.com" or "example.com.evil.net".
    A leading "*." or "." on a domain is accepted and means the same thing.
    """
    host = host.lower().rstrip(".")
    for domain in domains:
        domain = domain.lower().lstrip("*.").rstrip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return True
    return False


class ScopeManager:
    """Filters traffic to prevent noise in the LLM context window."""

    def __init__(self, config: ScopeConfig):
        self.config = config

    def is_allowed(self, flow: http.HTTPFlow) -> bool:
        if flow.metadata.get(AUTH_REJECTED_KEY):
            return False
        if self.config.allowed_domains:
            if not host_in_scope(flow.request.host, self.config.allowed_domains):
                return False

        path = flow.request.path.lower().split("?")[0]
        if any(path.endswith(ext) for ext in self.config.ignore_extensions):
            return False

        if flow.request.method in self.config.ignore_methods:
            return False

        return True

    def update_domains(self, domains: List[str]):
        self.config.allowed_domains = domains
