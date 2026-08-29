"""Authorisation scope guard.

An assurance tool that performs external checks against a third party is only
legitimate when the target is in scope. This module is the single gate every
outbound probe passes through: a target must appear on a configured allow
list, must not resolve to a protected network range, and can never be one of
the well known domains on the built in deny list, whatever the config says.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .errors import ScopeError

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Never assessable, regardless of configuration. These are here so a copied
# example config or a careless allow list entry cannot turn this tool into an
# unauthorised scanner of somebody else's production estate.
HARD_DENY = frozenset(
    {
        "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
        "whatsapp.com", "x.com", "twitter.com", "linkedin.com", "microsoft.com",
        "apple.com", "amazon.com", "netflix.com", "github.com", "cloudflare.com",
        "tiktok.com", "reddit.com", "wikipedia.org", "openai.com", "anthropic.com",
    }
)


def normalise(target: str) -> str:
    """Lowercase, strip a scheme, a port, a path and a trailing dot."""
    value = target.strip().lower()
    for scheme in ("https://", "http://"):
        if value.startswith(scheme):
            value = value[len(scheme):]
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    if ":" in value and not value.count(":") > 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def registrable(host: str) -> str:
    """Last two labels, which is the comparison unit for the deny list."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_protected_ip(host: str) -> bool:
    """True for loopback, link local, private and reserved addresses."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


@dataclass
class ScopeGuard:
    """Decides whether a target may be probed."""

    allow: frozenset[str] = field(default_factory=frozenset)
    allow_private: bool = False
    require_authorisation: bool = True
    authorised: bool = False

    @classmethod
    def from_config(cls, cfg: dict) -> ScopeGuard:
        section = cfg.get("scope", {}) or {}
        return cls(
            allow=frozenset(normalise(d) for d in section.get("allow", [])),
            allow_private=bool(section.get("allow_private", False)),
            require_authorisation=bool(section.get("require_authorisation", True)),
        )

    def authorise(self, confirmed: bool) -> ScopeGuard:
        """Record the operator's explicit confirmation for this run."""
        self.authorised = bool(confirmed)
        return self

    def check(self, target: str) -> str:
        """Return the normalised target, or raise ScopeError explaining why not."""
        host = normalise(target)
        if not host:
            raise ScopeError("target is empty")

        if is_protected_ip(host):
            if not self.allow_private:
                raise ScopeError(f"{host} is a protected address and scope.allow_private is false")
            return host

        if not _HOSTNAME.match(host):
            raise ScopeError(f"{host!r} is not a valid hostname")

        if registrable(host) in HARD_DENY:
            raise ScopeError(
                f"{host} is on the built in deny list and can never be assessed by this tool"
            )

        if self.require_authorisation and not self.authorised:
            raise ScopeError(
                "external checks require explicit authorisation; pass --i-am-authorised "
                "to confirm you have written permission to assess these targets"
            )

        if self.allow and host not in self.allow and registrable(host) not in self.allow:
            raise ScopeError(f"{host} is not on the configured scope.allow list")

        return host

    def permits(self, target: str) -> bool:
        try:
            self.check(target)
        except ScopeError:
            return False
        return True
