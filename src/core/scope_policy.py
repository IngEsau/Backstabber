from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List

from .config import get_config_store


class ScopePolicyError(ValueError):
    pass


class ScopePolicy:
    def __init__(self, config_path=None):
        self.config = get_config_store(config_path)

    @property
    def max_scan_targets(self) -> int:
        return self.config.max_scan_targets

    @property
    def rate_limit(self) -> int:
        return self.config.rate_limit

    @property
    def allowed_ranges(self) -> List[ipaddress._BaseNetwork]:
        ranges = []
        for cidr in self.config.allowed_ranges:
            try:
                ranges.append(ipaddress.ip_network(cidr, strict=False))
            except Exception:
                continue
        return ranges

    @property
    def excluded_targets(self) -> List[str]:
        return self.config.excluded_targets

    def validate_network(self, ip_range: str) -> ipaddress._BaseNetwork:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except Exception as exc:
            raise ScopePolicyError(f"Invalid IP range '{ip_range}': {exc}") from exc

        if self.allowed_ranges:
            if not any(network.subnet_of(allowed) for allowed in self.allowed_ranges):
                raise ScopePolicyError(
                    f"IP range '{ip_range}' is outside configured allowed ranges: {self.config.allowed_ranges}"
                )

        hosts = self._host_count(network)
        if hosts > self.max_scan_targets:
            raise ScopePolicyError(
                f"IP range '{ip_range}' contains {hosts} hosts, which exceeds the configured max_scan_targets={self.max_scan_targets}"
            )
        return network

    def filter_targets(self, ips: Iterable[str]) -> List[str]:
        filtered = []
        for ip in ips:
            if ip in self.excluded_targets:
                continue
            if self.allowed_ranges:
                address = ipaddress.ip_address(ip)
                if not any(address in allowed for allowed in self.allowed_ranges):
                    continue
            filtered.append(ip)
        return filtered

    @staticmethod
    def _host_count(network: ipaddress._BaseNetwork) -> int:
        if network.version == 4 and network.prefixlen < 31:
            return max(0, network.num_addresses - 2)
        return network.num_addresses
