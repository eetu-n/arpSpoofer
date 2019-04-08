import socket


class Interface:
    def __init__(self, name: str, netmask: str, addr: str, hwaddr: str):
        self.name = name
        self.netmask = netmask
        self.addr = addr
        self.hwaddr = hwaddr
        self.host = Host(addr, hwaddr)

    def get_name(self):
        return self.name

    def get_netmask(self):
        return self.netmask

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr

    def get_host(self):
        return self.host


class Host:
    def __init__(self, addr: str, hwaddr: str):
        self.addr = addr
        self.hwaddr = hwaddr

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr


class Destination:
    def __init__(self, url: str = ""):
        self.ip_list = self.find_ip_list(url)
        self.url = url

    def get_ip_list(self):
        return self.ip_list

    def get_url(self):
        return self.url

    @staticmethod
    def find_ip_list(url):
        ip_list = []
        for result in socket.getaddrinfo(url, 0, 0, 0, 0):
            result_ip = result[-1][0]
            if result_ip not in ip_list:
                ip_list.append(result_ip)

        return ip_list
