import scapy
import netifaces

def list_interfaces():
    # ID for the IP address information on this system
    inet_id = netifaces.AF_INET

    interfaces = []
    for interface_name in sorted(netifaces.interfaces()):
        int_ip_data = netifaces.ifaddresses(interface_name)
        inet_values = int_ip_data.get(inet_id)

        try:
            inet_values = int_ip_data[inet_id][0]
        except TypeError:
            inet_values = None
            continue
        except KeyError:
            inet_values = None
            continue

        netmask = inet_values.get("netmask")
        addr = inet_values.get("addr")

        print(interface_name)
        print(netmask)


list_interfaces()
