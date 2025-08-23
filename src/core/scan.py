from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, conf, send, get_if_addr, get_working_if
from core.scanner_adapter import get_default_scanner
from concurrent.futures import ThreadPoolExecutor

#---------------#
import asyncio
import ipaddress
import logging
import netifaces
import json
#---------------#

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def _fix_scapy_routing():
    try:
        if_addr = get_if_addr(conf.iface)
        if if_addr and "0.0.0.0" not in if_addr:
            conf.route.add(net="0.0.0.0/0", gw="0.0.0.0", dev=conf.iface)
    except Exception as e:
        logger.debug(f"Error fixing routing: {e}")


def aggregate_scan_results(all_alive_hosts: list, discovered_hosts_with_ports: dict, own_ip: str = None, gateway_ip: str = None) -> dict:
    """
    Aggregate scan results into a concise summary.
    - all_alive_hosts: list of IPs that responded to discovery (ARP/ICMP)
    - discovered_hosts_with_ports: dict mapping ip -> list_of_open_ports
    - own_ip, gateway_ip: optional to exclude from poisoning candidates
    """
    total_alive = len(all_alive_hosts)
    total_hosts_with_open = len(discovered_hosts_with_ports)
    total_open_ports = sum(len(ports) for ports in discovered_hosts_with_ports.values())

    # simple heuristic for active subnets: /24 by first three octets
    networks = set()
    for ip in all_alive_hosts:
        try:
            network = ".".join(ip.split(".")[:3]) + ".0/24"
            networks.add(network)
        except Exception:
            continue
    active_subnets = len(networks)

    # ARP poisoning candidates: hosts with open ports, excluding own/gateway
    candidates = []
    for ip, ports in discovered_hosts_with_ports.items():
        if own_ip and ip == own_ip:
            continue
        if gateway_ip and ip == gateway_ip:
            continue
        candidates.append({"ip": ip, "open_ports": ports, "score": len(ports)})
    candidates.sort(key=lambda x: x["score"], reverse=True)

    return {
        "total_alive_hosts": total_alive,
        "total_hosts_with_open_ports": total_hosts_with_open,
        "total_open_ports": total_open_ports,
        "active_subnets": active_subnets,
        "arp_poison_candidates": [c["ip"] for c in candidates],
    }


class AsyncScanner(QThread):
    """
    Asynchronous scanner run in a QThread.
    Emits:
      - result_line (str) : textual log messages
      - host_discovered (ip, open_ports_list) : when a host with open ports is found
      - progress_update (completed, total) : progress tracking
      - finished () : when scan ends
    """
    result_line = pyqtSignal(str)
    host_discovered = pyqtSignal(str, list)
    progress_update = pyqtSignal(int, int)
    finished = pyqtSignal()

    def __init__(self, ip_range, ports="1-1024", iface=None, parent=None):
        super().__init__(parent)
        self.ip_range = ip_range
        self.ports = self._parse_ports(ports)
        self.iface = iface
        self._cancel_requested = False
        self.total_hosts = 0
        self.completed_hosts = 0
        # mapping host_ip -> list_of_open_ports discovered during scanning
        self.discovered_hosts_with_ports = {}

        conf.verb = 0
        self._configure_scapy_interface()
        _fix_scapy_routing()

    def _configure_scapy_interface(self):
        try:
            if not self.iface:
                self.iface = get_working_if()
            conf.iface = self.iface
            if_addr = get_if_addr(self.iface)
            if if_addr and "0.0.0.0" not in if_addr:
                conf.route.add(net="0.0.0.0/0", gw="0.0.0.0", dev=self.iface)
            self.result_line.emit(f"[*] Using network interface: {self.iface}")
        except Exception as e:
            self.result_line.emit(f"[!] Interface error: {str(e)}")

    def _parse_ports(self, port_str):
        """ Converts a string of ports to a list of integers """
        ports = set()
        for part in port_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def _generate_ips(self):
        """ Generates all IP addresses in the given range """
        try:
            network = ipaddress.ip_network(self.ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Error on IP range: {e}")
            return []

    async def _discover_hosts(self):
        """
        Discover active hosts using ARP (for local networks) and ICMP (for any network)
        """
        active_hosts = set()
        ip_list = self._generate_ips()

        try:
            iface_used = self.iface or conf.iface
            if iface_used is None:
                iface_used = conf.iface
            own_addrs = netifaces.ifaddresses(iface_used).get(netifaces.AF_INET, [])
            own_ip = own_addrs[0]['addr'] if own_addrs else 'unknown'
            self.result_line.emit(f"[*] Using interface: {iface_used}, local IP: {own_ip}")
        except Exception as e:
            self.result_line.emit(f"[!] Could not fetch interface info: {e}")

        self.result_line.emit(f"[*] IP list size to scan: {len(ip_list)}")

        # ARP scan (local networks: using iface)
        try:
            arp = ARP(pdst=self.ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            ans, _ = await asyncio.to_thread(srp, packet, timeout=2, verbose=0, iface=self.iface)
            for _, rcv in ans:
                active_hosts.add(rcv.psrc)
                self.result_line.emit(f"[ARP] Acive HOST: {rcv.psrc}")
        except Exception as e:
            logger.error(f"Error on ARP scan: {e}")

        # ICMP scan for hosts that did not respond to ARP
        icmp_tasks = []
        for ip in ip_list:
            if ip not in active_hosts:
                icmp_tasks.append(self._icmp_ping(ip))

        # Process ICMP results in parallel
        icmp_results = await asyncio.gather(*icmp_tasks)
        for ip, is_active in icmp_results:
            if is_active:
                active_hosts.add(ip)
                self.result_line.emit(f"[ICMP] Active HOST: {ip}")

        return list(active_hosts)

    async def _icmp_ping(self, ip):
        """ Performs an ICMP ping to a specific IP address """
        try:
            packet = IP(dst=ip)/ICMP()
            response = await asyncio.to_thread(sr1, packet, timeout=1, verbose=0)
            return (ip, response is not None)
        except OSError as e:
            if e.errno == 9:
                return (ip, False)
            else:
                raise
        except Exception as e:
            return (ip, False)

    async def _scan_ports(self, host):
        """ Scans TCP ports on a specific host asynchronously """
        if self._cancel_requested:
            return []

        open_ports = []
        self.result_line.emit(f"[*] Scanning {host}...")

        # Semaphore to control concurrency (maximum 100 simultaneous ports)
        sem = asyncio.Semaphore(100)

        async def check_port(port):
            "Check if a specific port is open"
            async with sem:
                if self._cancel_requested:
                    return None

                try:
                    packet = IP(dst=host)/TCP(dport=port, flags="S")
                    response = await asyncio.to_thread(sr1, packet, timeout=1, verbose=0)

                    if response and response.haslayer(TCP):
                        flags = response.getlayer(TCP).flags
                        if flags == 0x12:  # SYN-ACK
                            # Send RST to close the connection
                            try:
                                rst_pkt = IP(dst=host)/TCP(dport=port, flags="R")
                                await asyncio.to_thread(send, rst_pkt, verbose=0)
                                return port
                            except OSError as e:
                                if e.errno != 9:
                                    raise
                                return port
                except OSError as e:
                    if e.errno == 9:
                        return None
                    else:
                        raise
                except Exception:
                    pass
                return None

        # Create and run tasks for all ports
        tasks = [check_port(port) for port in self.ports]
        for future in asyncio.as_completed(tasks):
            port_result = await future
            if port_result is not None:
                open_ports.append(port_result)
                self.result_line.emit(f"{host}:{port_result} [OPEN]")

        return open_ports

    #-------------#
    # MAIN METHOD #
    #-------------#

    def run(self):
        """ Main method that runs the scan in a separate thread """
        self._cancel_requested = False
        self.completed_hosts = 0
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Phase 1: Host Discovery
            self.result_line.emit("[*] Starting host discovery...")
            hosts = loop.run_until_complete(self._discover_hosts())

            if not hosts:
                self.result_line.emit("[!] No active hosts")
                self.finished.emit()
                return

            self.result_line.emit(f"[+] Active hosts discovered: {len(hosts)}")
            self.total_hosts = len(hosts)

            # Phase 2: Port Scanning by Host (adapter first, fallback to scapy)
            self.result_line.emit("[*] Starting port scan (adapter preferred)...")

            # prepare ports string for nmap adapter
            ports_str = ",".join(str(p) for p in self.ports)

            scanner = None
            try:
                scanner = get_default_scanner(prefer="nmap3")
                self.result_line.emit("[*] Scanner adapter initialized.")
            except Exception as e:
                self.result_line.emit(f"[!] Scanner adapter not available, will fallback to scapy: {e}")
                scanner = None

            if scanner:
                # Run adapter scans in threads to avoid blocking the event loop
                def scan_host_sync(host):
                    """
                    Synchronous helper executed in a threadpool.
                    Returns (host, list_of_open_ports) or (host, None) on error.
                    """
                    try:
                        nres = scanner.scan(host, ports=ports_str)
                        open_ports = []
                        if nres and isinstance(nres.get("hosts"), list):
                            for h in nres["hosts"]:
                                if h.get("ip") == host:
                                    for p in h.get("open_ports", []):
                                        state = str(p.get("state", "")).lower()
                                        if "open" in state:
                                            try:
                                                open_ports.append(int(p.get("port")))
                                            except Exception:
                                                pass
                                    break
                        return host, open_ports
                    except Exception as exc:
                        # return None to signal fallback/error for this host
                        return host, None

                # execute scans concurrently in a small thread pool
                results = []
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [loop.run_in_executor(executor, scan_host_sync, host) for host in hosts]
                    results = loop.run_until_complete(asyncio.gather(*futures))

                # process results
                for host, open_ports in results:
                    if open_ports is None:
                        # adapter failed for this host: fallback to scapy async scanner
                        self.result_line.emit(f"[!] Adapter failed for {host}, falling back to scapy async scan")
                        open_ports = loop.run_until_complete(self._scan_ports(host))
                    if open_ports:
                        # emit and save
                        self.host_discovered.emit(host, open_ports)
                        try:
                            self.discovered_hosts_with_ports[host] = open_ports
                        except Exception:
                            pass
                        self.result_line.emit(f"{host}:{open_ports} [OPEN] (via adapter/fallback)")
                    else:
                        self.result_line.emit(f"{host} - no open ports found")

            else:
                # fallback: original async Scapy-based host processing
                host_tasks = [self._process_host(host) for host in hosts]
                loop.run_until_complete(asyncio.gather(*host_tasks))

            self.result_line.emit("[+] Scan finished")

            # --------------------------
            # Aggregate results and print/export summary
            # --------------------------
            try:
                own_ip = None
                try:
                    own_ip = get_if_addr(self.iface) if self.iface else get_if_addr(conf.iface)
                except Exception:
                    own_ip = None

                gateway_ip = None
                try:
                    gws = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, ())
                    gateway_ip = gws[0] if gws else None
                except Exception:
                    gateway_ip = None

                summary = aggregate_scan_results(hosts, self.discovered_hosts_with_ports, own_ip=own_ip, gateway_ip=gateway_ip)

                # Emit summary lines
                self.result_line.emit("[+] Scan completed successfully")
                ts = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.result_line.emit(f"Network scan summary ({ts}):")
                self.result_line.emit(f"Total hosts discovered (alive): {summary['total_alive_hosts']}")
                self.result_line.emit(f"Hosts with open ports: {summary['total_hosts_with_open_ports']}")
                self.result_line.emit(f"Total open ports found: {summary['total_open_ports']}")
                self.result_line.emit(f"Active subnets detected: {summary['active_subnets']}")
                self.result_line.emit(f"ARP poisoning candidates: {summary['arp_poison_candidates'] or 'None'}")

                # Export results to logs as JSON (tools consumption)
                try:
                    export_obj = {
                        "timestamp": ts,
                        "alive_hosts": hosts,
                        "hosts_with_open_ports": self.discovered_hosts_with_ports,
                        "summary": summary
                    }
                    with open("logs/scan_results_for_tools.json", "w") as fh:
                        json.dump(export_obj, fh, indent=2)
                    self.result_line.emit("[i] Exported scan results to logs/scan_results_for_tools.json")
                except Exception as e:
                    self.result_line.emit(f"[!] Failed to export scan results: {e}")
            except Exception as e:
                # protect the main flow from any summary error
                self.result_line.emit(f"[!] Error while generating summary: {e}")

        except Exception as e:
            self.result_line.emit(f"[!] Fatal error: {str(e)}")
            logger.exception("Error during scan")
        finally:
            loop.close()
            self.finished.emit()

    async def _process_host(self, host):
        """ Processes an individual host (discovery + port scanning) """
        if self._cancel_requested:
            return

        open_ports = await self._scan_ports(host)
        if open_ports:
            self.host_discovered.emit(host, open_ports)
            # save to internal collection for final summary and external exports
            try:
                self.discovered_hosts_with_ports[host] = open_ports
            except Exception:
                pass

        self.completed_hosts += 1
        self.progress_update.emit(self.completed_hosts, self.total_hosts)

    def cancel(self):
        """ Request cancellation of the scan """
        self._cancel_requested = True
        self.result_line.emit("[!] Aborting Scan...")