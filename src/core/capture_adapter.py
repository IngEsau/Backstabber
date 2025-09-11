# src/core/capture_adapter.py

from typing import List, Dict, Optional, Tuple
import logging
import netifaces
import shutil

logger = logging.getLogger(__name__)


def list_interfaces() -> List[Dict[str, Optional[str]]]:
    """
    Return a list of network interfaces with a small info dict for each:
    [
      {"name": "eth0", "ipv4": "192.168.1.74", "netmask": "255.255.255.0", "mac": "aa:bb:cc:..."},
      ...
    ]

    Uses netifaces. This is a best-effort helper: some interfaces may have None values.
    """
    interfaces = []
    for iface in netifaces.interfaces():
        info = {"name": iface, "ipv4": None, "netmask": None, "mac": None}
        try:
            addrs = netifaces.ifaddresses(iface)
            # IPv4
            inet = addrs.get(netifaces.AF_INET)
            if inet and len(inet) > 0:
                info["ipv4"] = inet[0].get("addr")
                info["netmask"] = inet[0].get("netmask")
            # MAC / link
            link = addrs.get(netifaces.AF_LINK)
            if link and len(link) > 0:
                # some platforms return 'addr' as MAC
                info["mac"] = link[0].get("addr")
        except Exception as e:
            logger.debug(f"list_interfaces: cannot read info for {iface}: {e}")
        interfaces.append(info)
    # Put likely "default" interface first if possible
    default = get_default_interface()
    if default:
        interfaces.sort(key=lambda x: 0 if x.get("name") == default else 1)
    return interfaces


def get_default_interface() -> Optional[str]:
    """
    Return the interface name used for the system default gateway (IPv4), or None.
    Uses netifaces.gateways(). Example: ('192.168.1.1', 'eth0').
    """
    try:
        gws = netifaces.gateways()
        default = gws.get("default", {})
        if default:
            gw = default.get(netifaces.AF_INET)
            if gw and len(gw) >= 2:
                return gw[1]
    except Exception as e:
        logger.debug(f"get_default_interface: error determining default interface: {e}")
    return None


def check_tshark_installed() -> bool:
    """
    Return True if 'tshark' binary is available in PATH. Pyshark requires tshark.
    """
    return shutil.which("tshark") is not None


def supported_filters() -> List[str]:
    """
    Return a list of preset filter keys (user-visible strings).
    Keep these stable; UI can use them in a dropdown.
    """
    return [
        "All Traffic",
        "ARP",
        "Only ARP",
        "Attacker <-> Victim",
        "Attacker <-> Gateway",
        "MITM (Victim + Gateway)",
        "Custom BPF"
    ]


def map_filter(
    preset_key: str,
    victim_ip: Optional[str] = None,
    attacker_ip: Optional[str] = None,
    gateway_ip: Optional[str] = None
) -> Tuple[str, Optional[str]]:
    """
    Map a preset key to a BPF filter string and an optional display filter.

    Returns (bpf_filter, display_filter)
    - bpf_filter: capture filter (BPF) used by pyshark.LiveCapture(..., bpf_filter=bpf)
    - display_filter: optional tshark/pyshark display filter (higher-level) or None

    Examples of mapping:
      - "All Traffic" -> ("", None)
      - "ARP" -> ("arp", None)
      - "Attacker <-> Victim" -> (f"host {attacker_ip} and host {victim_ip}", None)
      - "MITM (Victim + Gateway)" -> (f"host {victim_ip} or host {gateway_ip}", None)
      - "Custom BPF" -> caller provides custom BPF as 'attacker_ip' parameter (we return it directly)
    """
    key = (preset_key or "").strip()

    # sanitize inputs (no heavy validation here)
    v = victim_ip.strip() if victim_ip else None
    a = attacker_ip.strip() if attacker_ip else None
    g = gateway_ip.strip() if gateway_ip else None

    # Default: capture everything
    if key == "All Traffic":
        return ("", None)

    if key in ("ARP", "Only ARP"):
        return ("arp", None)

    if key == "Attacker <-> Victim":
        if a and v:
            return (f"host {a} and host {v}", None)
        else:
            # fallback to empty capture filter but UI should warn caller that IPs missing
            return ("", None)

    if key == "Attacker <-> Gateway":
        if a and g:
            return (f"host {a} and host {g}", None)
        else:
            return ("", None)

    if key == "MITM (Victim + Gateway)":
        if v and g:
            # capture traffic involving victim or gateway (useful for MITM analysis)
            return (f"host {v} or host {g}", None)
        else:
            return ("", None)

    if key == "Custom BPF":
        # For convenience, caller may pass custom BPF in 'attacker_ip' parameter
        # (we avoid adding new args to keep API simple)
        custom = attacker_ip or victim_ip or gateway_ip or ""
        return (custom, None)

    # Unknown key: return empty (capture all)
    return ("", None)
