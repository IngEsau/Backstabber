import netifaces
from ipaddress import IPv4Network, IPv4Address

def in_same_subnet(ip1, ip2):
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for a in addrs:
            net = IPv4Network(f"{a['addr']}/{a['netmask']}", strict=False)
            if IPv4Address(ip1) in net and IPv4Address(ip2) in net:
                return True
    return False

def get_default_gateway():
    gws = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, ())
    return [gws[0]] if gws else []


def evaluate_best_target(nmap_output: str, hosts: list[str], own_ip: str, gateway_ip: str) -> str | None:
    """
    Devuelve la IP con mayor número de puertos abiertos, 
    descartando own_ip y gateway_ip. Retorna None si no hay
    ningún host válido con al menos 1 puerto abierto.
    """
    def score_host(ip: str) -> int:
        if ip == own_ip or ip == gateway_ip:
            return -1        
        marker = f"Nmap scan report for {ip}"
        lines = nmap_output.splitlines()
        score = 0
        inside = False
        for line in lines:
            if marker in line:
                inside = True
                continue
            if inside:                
                if line.startswith("Nmap scan report for"):
                    break
                # Each line with "open" + 1
                if "open" in line:
                    score += 1
        return score
    scored = [(ip, score_host(ip)) for ip in hosts]    
    scored = [t for t in scored if t[1] > 0]    
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[0][0] if scored else None