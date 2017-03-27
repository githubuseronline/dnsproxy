#!/usr/bin/python
import sys
import asyncio
import socket
import time
import concurrent
import threading
import ctypes

DNS_LIST = [
    '8.8.8.8',
    '8.8.4.4'
]

DNS_PORT = 53
PACKET_SIZE = 65536
QUERY_TTL = 10
LOOP = asyncio.get_event_loop()
POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10)


class DnsHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ('id', ctypes.c_uint16),
        ('qr', ctypes.c_uint16,       1),
        ('op_code', ctypes.c_uint16,  4),
        ('aa', ctypes.c_uint16,       1),
        ('tc', ctypes.c_uint16,       1),
        ('rd', ctypes.c_uint16,       1),
        ('ra', ctypes.c_uint16,       1),
        ('z', ctypes.c_uint16,        3),
        ('r_code', ctypes.c_uint16,   4),
        ('qd_count', ctypes.c_uint16),
        ('an_count', ctypes.c_uint16),
        ('ns_count', ctypes.c_uint16),
        ('ar_count', ctypes.c_uint16),
    ]

    def load(self, _bytes):
        fit = min(len(_bytes), ctypes.sizeof(self))
        ctypes.memmove(ctypes.addressof(self), _bytes, fit)


class DNS(object):
    def __init__(self, dns_list):
        try:
            infolist = socket.getaddrinfo(None, DNS_PORT, 0, socket.SOCK_DGRAM, 0,
                                          socket.AI_PASSIVE)
        except socket.gaierror as e:
            print('Name service failure:', e.args[1])
            sys.exit(1)

        info = infolist[0]
        self.sock = socket.socket(*info[:3])
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind(info[4])
        except socket.error as e:
            print('Network failure', e.args[1])

        self.remote_dns_list = dns_list

    @property
    def get_sock(self):
        return self.sock


class QueryHandler(object):
    def __init__(self, remote):
        self.ttl = QUERY_TTL
        self.last_update = time.time()
        self.q_key = None
        self.cache = PoorCache.instance()

        try:
            infolist = socket.getaddrinfo(remote, DNS_PORT, 0, socket.SOCK_DGRAM, 0,
                                          socket.AI_ADDRCONFIG | socket.AI_V4MAPPED)
        except socket.gaierror as e:
            print('Name service failure:', e.args[1])
            sys.exit(1)

        info = infolist[0]
        self.socket = socket.socket(*info[:3])

    def is_expired(self):
        return time.time() - self.last_update > self.ttl

    def handle(self, sock):
        try:
            data, addr = self.socket.recvfrom(PACKET_SIZE)
            self.last_update = time.time()
        except Exception as e:
            pass
        if data:
            sock.sendto(data, self.q_key[0])
            LOOP.remove_reader(self.socket)

    def sendto(self, data, addr):
        try:
            self.last_update = time.time()
            self.socket.sendto(data, addr)
        except Exception as e:
            print('cant send')

    def close(self):
        try:
            self.socket.close()
        except Exception as e:
            pass


class PoorCache(object):
    _lock = threading.Lock()

    @staticmethod
    def instance():
        if not hasattr(PoorCache, '_instance'):
            with PoorCache._lock:
                if not hasattr(PoorCache, '_instance'):
                    PoorCache._instance = PoorCache()
        return PoorCache._instance


def create_server(dns):
    # server context
    queries = {}
    cache = PoorCache.instance()
    dns_header = DnsHeader()
    # server context

    def server_handler():
        try:
            data, sender = dns.get_sock.recvfrom(PACKET_SIZE)
        except Exception as e:
            pass
        if data is not None:
            dns_header.load(data)
            if not dns_header.qr:
                for remote in dns.remote_dns_list:
                    q_key = (sender, remote)
                    if q_key not in queries:
                        handler = QueryHandler(remote)
                        queries[q_key] = handler
                        queries[q_key].q_key = q_key

                        fd = queries[q_key].socket
                        LOOP.add_reader(fd, handler.handle, dns.get_sock)

                    POOL.submit(queries[q_key].sendto, data, (remote, DNS_PORT))

        remove_list = []

        for q_key in queries.keys():
            if queries[q_key].is_expired():
                remove_list.append(q_key)

        for q_key in remove_list:
            handler = queries[q_key]
            handler.close()
            del queries[q_key]

    return server_handler


def main():
    dns = DNS(dns_list=DNS_LIST)
    LOOP.add_reader(dns.get_sock, create_server(dns))
    LOOP.run_forever()

if __name__ == '__main__':
    main()

