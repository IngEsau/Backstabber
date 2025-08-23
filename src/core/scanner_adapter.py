from typing import Dict, List, Optional
import subprocess
import xml.etree.ElementTree as ET
import shutil

try:
    import nmap3  
    HAS_NMAP3 = True
except Exception:
    HAS_NMAP3 = False


class BaseScanner:
    """
    Base class that defines the scanner interface.
    """

    def scan(self, target: str, ports: str = "1-1024", extra_args: str = "") -> Dict:
        """
        Run a scan and return a standardized dict.
        Must be implemented by subclasses.
        """
        raise NotImplementedError


class SubprocessNmapScanner(BaseScanner):
    """
    Scanner implementation that runs the nmap binary with -oX - (XML stdout)
    and parses the XML to a standardized python dict.
    This is robust as long as the 'nmap' binary is present in PATH.
    """

    def __init__(self, nmap_path: Optional[str] = None):
        # Allow overriding nmap binary path, otherwise expect it in PATH
        self.nmap_path = nmap_path or shutil.which("nmap")
        if not self.nmap_path:
            raise FileNotFoundError("nmap binary not found in PATH. Please install nmap.")

    def scan(self, target: str, ports: str = "1-1024", extra_args: str = "") -> Dict:
        # Build nmap command: TCP SYN scan (-sS), XML output to stdout (-oX -)
        cmd = [self.nmap_path, "-sS", "-p", ports, "-oX", "-", target]
        if extra_args:
            cmd[1:1] = extra_args.split()  # insert extra args after binary
        proc = subprocess.run(cmd, capture_output=True, text=True)
        xml_out = proc.stdout or ""
        # If nmap returned error on stderr, include it in raw output for debugging
        raw = {"xml": xml_out, "stderr": proc.stderr}
        hosts = self._parse_nmap_xml(xml_out)
        return {"hosts": hosts, "raw": raw}

    def _parse_nmap_xml(self, xml_text: str) -> List[Dict]:
        """
        Parse nmap XML output and extract hosts and open ports.
        Returns a list of host dicts in the standardized format.
        """
        hosts: List[Dict] = []
        if not xml_text:
            return hosts
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            # malformed XML -> return empty hosts but keep raw xml in response
            return hosts

        # nmap XML namespace handling (if any)
        for host in root.findall("host"):
            addr = None
            hostname = None
            for addr_el in host.findall("address"):
                addr_type = addr_el.get("addrtype")
                if addr_type == "ipv4":
                    addr = addr_el.get("addr")
            # hostname
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")

            open_ports = []
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    portid = port_el.get("portid")
                    protocol = port_el.get("protocol")
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    state = state_el.get("state") if state_el is not None else None
                    service = service_el.get("name") if service_el is not None else None
                    try:
                        pnum = int(portid)
                    except Exception:
                        continue
                    open_ports.append({
                        "port": pnum,
                        "protocol": protocol,
                        "state": state,
                        "service": service
                    })

            if addr:
                hosts.append({
                    "ip": addr,
                    "hostname": hostname,
                    "open_ports": open_ports
                })
        return hosts


class Nmap3Scanner(BaseScanner):
    """
    Adapter for python3-nmap (nmap3). This implementation tries to use nmap3 if available.
    Because python3-nmap exposes several convenience methods, this adapter tries common method
    names dynamically and falls back to calling the SubprocessNmapScanner if necessary.

    The goal is to let your application call `scan()` without caring about the backend.
    """

    def __init__(self):
        if not HAS_NMAP3:
            raise ImportError("python3-nmap (nmap3) is not installed.")
        # instantiate the nmap3 scanner object
        self.scanner = nmap3.NmapScanner()

    def scan(self, target: str, ports: str = "1-1024", extra_args: str = "") -> Dict:
        """
        Attempt to run nmap via nmap3. We attempt several common method names.
        If no usable method is found or call fails, we fallback to subprocess implementation.
        """
        candidate_methods = [
            "scan_top_ports",  # common convenience method name in some wrappers
            "scan",            # generic name
            "nmap_scan",       # possible variations
            "nmap_version_detection",
            "scan_extended"    # hypothetical
        ]

        for name in candidate_methods:
            method = getattr(self.scanner, name, None)
            if callable(method):
                try:
                    # Try calling with basic signature first
                    raw = method(target)
                    normalized = self._try_normalize_raw(raw)
                    if normalized is not None:
                        return normalized
                except TypeError:
                    # try calling with extra args or ports if method signature differs
                    try:
                        raw = method(target, f"-p {ports} {extra_args}".strip())
                        normalized = self._try_normalize_raw(raw)
                        if normalized is not None:
                            return normalized
                    except Exception:
                        # not compatible, try next candidate
                        continue
                except Exception:
                    # unexpected runtime error using this method; try next
                    continue

        # final fallback: use SubprocessNmapScanner
        fallback = SubprocessNmapScanner()
        return fallback.scan(target, ports, extra_args)

    def _try_normalize_raw(self, raw) -> Optional[Dict]:
        """
        Attempt to convert nmap3 raw output into the standardized dict.
        nmap3 methods may return dicts or JSON-like objects; we try to handle
        safe common shapes. If we cannot normalize, return None to signal fallback.
        """
        # If raw is already a dict with structured data, try to extract hosts
        try:
            if isinstance(raw, dict):
                # check common keys
                if "hosts" in raw and isinstance(raw["hosts"], list):
                    hosts_out = []
                    for h in raw["hosts"]:
                        ip = h.get("ip") or h.get("addresses", {}).get("ipv4")
                        # try to get ports list in multiple possible places
                        ports = []
                        if "ports" in h and isinstance(h["ports"], list):
                            for p in h["ports"]:
                                ports.append({
                                    "port": int(p.get("port", 0)),
                                    "protocol": p.get("protocol"),
                                    "state": p.get("state"),
                                    "service": p.get("service", {}).get("name") if p.get("service") else p.get("service")
                                })
                        hosts_out.append({"ip": ip, "hostname": h.get("hostname"), "open_ports": ports})
                    return {"hosts": hosts_out, "raw": raw}
            # If raw is a string (maybe textual output), try parsing as XML
            if isinstance(raw, str) and raw.strip().startswith("<"):
                # assume XML string from nmap; reuse Subprocess parser
                fallback = SubprocessNmapScanner()
                hosts = fallback._parse_nmap_xml(raw)
                return {"hosts": hosts, "raw": {"xml": raw}}
        except Exception:
            pass
        return None


# Factory function
def get_default_scanner(prefer: str = "nmap3") -> BaseScanner:
    """
    Return a scanner instance based on availability and preference.
    prefer: "nmap3" or "subprocess"
    """
    if prefer == "nmap3" and HAS_NMAP3:
        try:
            return Nmap3Scanner()
        except Exception:
            # fall through to subprocess
            pass
    # final fallback (or prefer subprocess)
    return SubprocessNmapScanner()