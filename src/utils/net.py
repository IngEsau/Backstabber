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