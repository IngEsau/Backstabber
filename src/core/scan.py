from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
import ipaddress
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, conf, send, get_if_addr
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def _fix_scapy_routing():
    """ Soluciona el problema de ruteo en Scapy"""
    try:
        if_addr = get_if_addr(conf.iface)
        if if_addr and "0.0.0.0" not in if_addr:
            conf.route.add(net="0.0.0.0/0", gw="0.0.0.0", dev=conf.iface)
    except Exception as e:
        logger.debug(f"Error fixing routing: {e}")

class AsyncScanner(QThread):
    result_line = pyqtSignal(str)          
    host_discovered = pyqtSignal(str, list)  
    progress_update = pyqtSignal(int, int)  
    finished = pyqtSignal()                

    def __init__(self, ip_range, ports="1-1024", iface=None, parent=None):        
        super().__init__(parent)
        self.ip_range = ip_range
        self.ports = self._parse_ports(ports)
        self.iface = iface or conf.iface
        self._cancel_requested = False
        self.total_hosts = 0
        self.completed_hosts = 0
        
        # Configuración de Scapy
        conf.verb = 0    
        _fix_scapy_routing()

    def _parse_ports(self, port_str):
        """Convierte una cadena de puertos en una lista de enteros"""
        ports = set()
        for part in port_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def _generate_ips(self):
        """Genera todas las direcciones IP del rango dado"""
        try:
            network = ipaddress.ip_network(self.ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Error on IP range: {e}")
            return []

    async def _discover_hosts(self):
        """Descubre hosts activos usando ARP (para redes locales) e ICMP (para cualquier red)"""
        active_hosts = set()
        ip_list = self._generate_ips()
        self.total_hosts = len(ip_list)
        
        if not ip_list:
            self.result_line.emit(f"[!] Invalid IP range: {self.ip_range}")
            return []

        # Escaneo ARP (redes locales)
        try:
            arp = ARP(pdst=self.ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Ejecutar en hilo separado (srp es bloqueante)
            ans, _ = await asyncio.to_thread(srp, packet, timeout=2, verbose=0, iface=self.iface)
            for _, rcv in ans:
                active_hosts.add(rcv.psrc)
                self.result_line.emit(f"[ARP] Acive HOST: {rcv.psrc}")
        except Exception as e:
            logger.error(f"Error on ARP scan: {e}")

        # Escaneo ICMP para hosts que no respondieron a ARP
        icmp_tasks = []
        for ip in ip_list:
            if ip not in active_hosts:
                icmp_tasks.append(self._icmp_ping(ip))
        
        # Procesar resultados ICMP en paralelo
        icmp_results = await asyncio.gather(*icmp_tasks)
        for ip, is_active in icmp_results:
            if is_active:
                active_hosts.add(ip)
                self.result_line.emit(f"[ICMP] Active HOST: {ip}")

        return list(active_hosts)

    async def _icmp_ping(self, ip):
        """Realiza un ping ICMP a una dirección IP específica"""
        try:
            packet = IP(dst=ip)/ICMP()
            # Ejecutar en hilo separado (sr1 es bloqueante)
            response = await asyncio.to_thread(sr1, packet, timeout=1, verbose=0, iface=self.iface)
            return (ip, response is not None)
        except Exception as e:
            logger.error(f"Error en ping a {ip}: {e}")
            return (ip, False)

    async def _scan_ports(self, host):
        """Escanea puertos TCP en un host específico de forma asíncrona"""
        if self._cancel_requested:
            return []

        open_ports = []
        self.result_line.emit(f"[*] Scanning {host}...")
        
        # Semáforo para controlar la concurrencia (máximo 100 puertos simultáneos)
        sem = asyncio.Semaphore(100)
        
        async def check_port(port):
            """Verifica si un puerto específico está abierto"""
            async with sem:
                if self._cancel_requested:
                    return None
                    
                try:
                    packet = IP(dst=host)/TCP(dport=port, flags="S")
                    #Hilo separado
                    response = await asyncio.to_thread(sr1, packet, timeout=1, verbose=0, iface=self.iface)
                    
                    if response and response.haslayer(TCP):
                        flags = response.getlayer(TCP).flags
                        if flags == 0x12:  # SYN-ACK
                            # Enviar RST para cerrar la conexión
                            rst_pkt = IP(dst=host)/TCP(dport=port, flags="R")
                            await asyncio.to_thread(send, rst_pkt, verbose=0)
                            return port
                except Exception as e:
                    logger.debug(f"Error on port {port}: {e}")
                return None
        
        # Crear y ejecutar tareas para todos los puertos
        tasks = [check_port(port) for port in self.ports]
        for future in asyncio.as_completed(tasks):
            port_result = await future
            if port_result is not None:
                open_ports.append(port_result)
                self.result_line.emit(f"{host}:{port_result} [OPEN]")
        
        return open_ports

    def run(self):
        """Método principal que ejecuta el escaneo en un hilo separado"""
        self._cancel_requested = False
        self.completed_hosts = 0
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Fase 1: Descubrimiento de hosts
            self.result_line.emit("[*] Starting host discovery...")
            hosts = loop.run_until_complete(self._discover_hosts())
            
            if not hosts:
                self.result_line.emit("[!] No active hosts")
                self.finished.emit()
                return
                
            self.result_line.emit(f"[+] Active hosts discovered: {len(hosts)}")
            self.total_hosts = len(hosts)
            
            # Fase 2: Escaneo de puertos por host
            self.result_line.emit("[*] Starting port scan...")
            host_tasks = [self._process_host(host) for host in hosts]
            loop.run_until_complete(asyncio.gather(*host_tasks))
            
            self.result_line.emit("[+] Scan finished")
            
        except Exception as e:
            self.result_line.emit(f"[!] Fatal error: {str(e)}")
            logger.exception("Error during scan")
        finally:
            loop.close()
            self.finished.emit()

    async def _process_host(self, host):
        """Procesa un host individual (descubrimiento + escaneo de puertos)"""
        if self._cancel_requested:
            return
            
        open_ports = await self._scan_ports(host)
        if open_ports:
            self.host_discovered.emit(host, open_ports)
        
        self.completed_hosts += 1
        self.progress_update.emit(self.completed_hosts, self.total_hosts)

    def cancel(self):
        """Solicita la cancelación del escaneo"""
        self._cancel_requested = True
        self.result_line.emit("[!] Aborting Scan...")