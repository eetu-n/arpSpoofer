import scapy
import netifaces


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

    selected_interface_id = input("Please choose a network interface:\n")
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
    # TODO: Implement method to list hosts with scapy.arping()
    host_list = []
    return host_list


def host_selector(interface: Interface):
    hosts = list_hosts(interface)
    print("Available hosts:\n")
    i = 0
    for host in hosts:
        print(i + ": " + host)
        i = i + 1

    selected_host_ids = input("Please select host(s) to sniff, comma separated list of IDs. Default = all:\n")

    selected_hosts = []

    if selected_host_ids is None or selected_host_ids.lower() == "all":
        selected_hosts = hosts
    else:
        # TODO: Convert csv into list of host IPs
        pass

    return selected_hosts


def main():
    selected_interface = interface_selector()
    hosts = host_selector(selected_interface)


main()
