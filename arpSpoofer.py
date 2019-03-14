import scapy
import netifaces


class Interface:
    def __init__(self, name, netmask, addr):
        self.name = name
        self.netmask = netmask
        self.addr = addr

    def getName(self):
        return self.name

    def getNetmask(self):
        return self.netmask

    def getAddr(self):
        return self.addr

def list_interfaces():
    # ID for the IP address information on this system
    inet_id = netifaces.AF_INET

    interfaces = []
    for interface_name in sorted(netifaces.interfaces()):
        int_ip_data = netifaces.ifaddresses(interface_name)

        try:
            inet_values = int_ip_data[inet_id][0]
        except TypeError:
            continue
        except KeyError:
            continue

        netmask = inet_values.get("netmask")
        addr = inet_values.get("addr")

        iface = Interface(interface_name, netmask, addr)

        interfaces.append(iface)


list_interfaces()
