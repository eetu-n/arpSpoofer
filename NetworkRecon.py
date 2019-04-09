import netifaces
from math import log
from DataStructures import *
import scapy.layers.l2
from scapy.all import *


class NetworkRecon:
    @staticmethod
    def list_interfaces():
        # ID for the IP address information on this system
        inet_id = netifaces.AF_INET
        link_id = netifaces.AF_LINK

        interfaces = []
        for interface_name in sorted(netifaces.interfaces()):
            int_ip_data = netifaces.ifaddresses(interface_name)
            hw_data = netifaces.ifaddresses(interface_name)

            try:
                inet_values = int_ip_data[inet_id][0]
                hw_values = hw_data[link_id][0]
            except TypeError:
                continue
            except KeyError:
                continue

            netmask = inet_values.get("netmask")
            addr = inet_values.get("addr")
            hwaddr = hw_values.get("addr")

            interface = Interface(interface_name, netmask, addr, hwaddr)

            interfaces.append(interface)

        return interfaces

    @staticmethod
    def list_hosts(interface: Interface):
        netmask = interface.get_netmask().split(".")
        ip = interface.get_addr().split(".")

        ip = [int(x) for x in ip]

        ip[3] = 0

        ip_str = ""

        for segment in ip:
            ip_str = ip_str + str(segment) + "."

        ip_str = ip_str[:-1]

        cidr = 0
        for portion in netmask:
            cidr = cidr + log(int(portion) + 1, 2)

        cidr = str(int(cidr))

        cidr_full = ip_str + "/" + cidr

        conf.iface = interface.get_name()

        print("Pinging IP Range...")
        tmp = scapy.layers.l2.arping(cidr_full, verbose=False)

        print()

        host_list = []

        for item in tmp[0]:
            tmp_host = Host(item[0].pdst, item[1].src)
            host_list.append(tmp_host)

        interface.set_active_hosts(host_list)

        return host_list
