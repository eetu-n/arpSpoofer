class Interface:
    def __init__(self, name, netmask, addr, hwaddr):
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
    def __init__(self, addr, hwaddr):
        self.addr = addr
        self.hwaddr = hwaddr

    def get_addr(self):
        return self.addr

    def get_hwaddr(self):
        return self.hwaddr
