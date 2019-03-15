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


def main():
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

    print("You selected: " + selected_interface.name)

main()
