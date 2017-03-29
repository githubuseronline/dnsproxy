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
]

DNS_PORT = 53
PACKET_SIZE = 65536
TTL = 10
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
    def __init__(self, remote, id, cached=False, domain=None, sender=None):
        self.last_update = time.time()
        self.q_key = None
        self.cache = PoorCache.instance()
        self.id = id
        self.cached = cached
        self.domain = domain
        self.sender = sender

        if remote is not None:
            try:
                infolist = socket.getaddrinfo(remote, DNS_PORT, 0, socket.SOCK_DGRAM, 0,
                                              socket.AI_ADDRCONFIG | socket.AI_V4MAPPED)
            except socket.gaierror as e:
                print('Name service failure:', e.args[1])
                sys.exit(1)

            info = infolist[0]
            self.socket = socket.socket(*info[:3])

    def is_expired(self):
        return time.time() - self.last_update > TTL

    def handle(self, sock):
        if not self.cached:
            try:
                data, _ = self.socket.recvfrom(PACKET_SIZE)
            except Exception as e:
                pass

            if data:
                domain = parse_domain(data[_DOMAIN:])
                self.cache.push(domain, data[_ID:])
                sock.sendto(data, self.sender)
                LOOP.remove_reader(self.socket)
        else:
            try:
                query = self.cache.get(self.domain)
                response = self.id + query
                sock.sendto(response, self.sender)
            except Exception as e:
                pass

    def sendto(self, data, addr):
        try:
            self.last_update = time.time()
            self.socket.sendto(data, addr)
        except Exception as e:
            pass

    def close(self):
        try:
            self.socket.close()
        except Exception as e:
            pass


class PoorCache(object):
    _lock = threading.Lock()

    def __init__(self):
        self.bag = {}
        self.size = 0xFF

    @staticmethod
    def instance():
        if not hasattr(PoorCache, '_instance'):
            with PoorCache._lock:
                if not hasattr(PoorCache, '_instance'):
                    PoorCache._instance = PoorCache()
        return PoorCache._instance

    def cached(self, key):
        if key in self.bag:
            return True
        return False

    def push(self, key, val):
        self.bag[key] = val

    def get(self, key):
        return self.bag[key]


_DOMAIN = ctypes.sizeof(DnsHeader)
_ID = 2


def parse_domain(query):
    domain = []
    for byte in query:
        if byte == 0: break
        if byte < 63:
            if not domain: continue
            domain.append(46)
            continue
        domain.append(byte)
    return tuple(domain)


def create_server(dns):
    # server context
    queries = {}
    cache = PoorCache.instance()
    dns_header = DnsHeader()
    cache_hits = 0
    total = 0
    last_info_time = time.time()
    # server context

    def server_handler():
        nonlocal cache_hits, total, last_info_time

        try:
            data, sender = dns.get_sock.recvfrom(PACKET_SIZE)
        except Exception as e:
            pass

        if data is not None:
            total += 1
            dns_header.load(data)
            domain = parse_domain(data[_DOMAIN:])
            _id = data[:_ID]

            if cache.cached(domain):
                handler = QueryHandler(None, id=_id,
                                       cached=True,
                                       domain=domain,
                                       sender=sender)
                POOL.submit(handler.handle, dns.get_sock)
                cache_hits += 1
            else:
                for remote in dns.remote_dns_list:
                    q_key = (sender, remote)
                    if q_key not in queries:
                        handler = QueryHandler(remote, id=_id,
                                               sender=sender)
                        queries[q_key] = handler
                        LOOP.add_reader(handler.socket, handler.handle, dns.get_sock)
                        POOL.submit(handler.sendto, data, (remote, DNS_PORT))

        # statical key list coz it is bad idea
        # to change dict with 'dynamic' iterator
        for _key in list(queries.keys()):
            if queries[_key].is_expired():
                del queries[_key]

        info_time = time.time() - last_info_time > TTL
        if info_time:
            if total:
                print('#     total: {}\n'
                      '#cache hits: {}\n'
                      '#    cache%: {:.0f}%\n'
                      '#cache size: {}\n'
                      '#   queries: {}'.format(total,
                                               cache_hits,
                                               cache_hits / total * 100,
                                               len(cache.bag),
                                               len(queries)))
            last_info_time = time.time()

    return server_handler


def main():
    dns = DNS(dns_list=DNS_LIST)
    LOOP.add_reader(dns.get_sock, create_server(dns))
    LOOP.run_forever()

if __name__ == '__main__':
    main()

