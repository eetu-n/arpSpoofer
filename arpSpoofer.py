import scapy
import netifaces

def list_interfaces():
    interfaces = []
    for interface_name in sorted(netifaces.interfaces()):
        print(interface_name)

list_interfaces()