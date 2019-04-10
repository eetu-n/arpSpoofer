import time
from collections import deque
from threading import Thread

from requests import post
from scapy.config import conf
from scapy.layers.inet import IP
from scapy.sendrecv import send, sniff
from scapy.utils import wrpcap

from DataStructures import Interface, Destination


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