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

            iface = Interface(interface_name, netmask, addr, hwaddr)

            interfaces.append(iface)

        return interfaces

    @staticmethod
    def list_hosts(interface: Interface):
        netmask = interface.get_netmask().split(".")
        ip = interface.get_addr().split(".")

        ip = [int(x) for x in ip]

        # TODO: This is bad, make not bad
        if ip[3] != 0:
            ip[3] = ip[3] - 1

        elif ip[2] != 0:
            ip[3] = 255
            ip[2] = ip[2] - 1

        elif ip[1] != 0:
            ip[3] = 255
            ip[2] = 255
            ip[1] = ip[1] - 1

        elif ip[0] != 0:
            ip[3] = 255
            ip[2] = 255
            ip[1] = 255
            ip[0] = ip[0] - 1

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
        tmp = scapy.layers.l2.arping(cidr_full)

        print()

        host_list = []

        for item in tmp[0]:
            tmp_host = Host(item[0].pdst, item[1].src)
            host_list.append(tmp_host)

        return host_list
