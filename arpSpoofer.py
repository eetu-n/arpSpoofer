import scapy.layers.l2
from scapy.all import conf
import netifaces
from math import log

class Interface:
    def __init__(self, name, netmask, addr):
        self.name = name
        self.netmask = netmask
        self.addr = addr

    def get_name(self):
        return self.name

    def get_netmask(self):
        return self.netmask

    def get_addr(self):
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

    return interfaces


def interface_selector():
    # TODO: Add error detection
    interfaces = list_interfaces()
    print("Available interfaces:")
    i = 0
    for interface in interfaces:
        print(str(i) + ": " + interface.name)
        i = i + 1

    print("")

    selected_interface_id = input("Please choose a network interface: ")

    print("")

    try:
        selected_interface_id = int(selected_interface_id)
        selected_interface = interfaces[selected_interface_id]

    except ValueError:
        i = 0
        for interface in interfaces:
            if interface.name == selected_interface_id:
                selected_interface = interfaces[i]
                break
            i = i + 1

    return selected_interface


def list_hosts(interface: Interface):
    netmask = interface.get_netmask().split(".")
    ip = interface.get_addr().split(".")

    ip = [int(x) for x in ip]

    # TODO: This is bad, make not bad
    if ip[3] != 0:
        ip[3] = ip[3]-1
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
        ip[0] = ip[0]-1

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
        host_list.append(item[0].pdst)

    return host_list


def host_selector(interface: Interface):
    # TODO: Add error detection
    hosts = list_hosts(interface)
    print("Available hosts:")
    i = 0
    for host in hosts:
        print(str(i) + ": " + host)
        i = i + 1

    print()

    target_1_id = input("Please select target #1: ")
    target_2_id = input("Please select target #2: ")

    target_1 = hosts[int(target_1_id)]
    target_2 = hosts[int(target_2_id)]

    selected_hosts = [target_1, target_2]

    return selected_hosts

def main():
    print("This is an ARP Spoofing tool.\n")
    selected_interface = interface_selector()
    targets = host_selector(selected_interface)
    print(targets)


main()
