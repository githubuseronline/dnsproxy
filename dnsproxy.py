import asyncio
import socket
import time
import concurrent


LOCAL_DNS = {
    'host': '0.0.0.0',
    'port': 53,
}

DNS_LIST = [
    '8.8.8.8'
]

PACKET_SIZE = 65536
TTL = 10
LOOP = asyncio.get_event_loop()
POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10)


class DNS(object):
    def __init__(self, bind, dns_list):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind['host'], bind['port']))
        self.remote_dns_list = dns_list

    @property
    def get_sock(self):
        return self.sock


class QueryHandler(object):
    def __init__(self, remote, ttl):
        self.ttl = ttl
        self.last_update = time.time()
        self.q_key = None

        addrs = socket.getaddrinfo(remote[0], 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
        AF, TYPE, PROTO, *rest = addrs[0]
        self.socket = socket.socket(AF, TYPE, PROTO)

    def is_expired(self):
         return time.time() - self.last_update > self.ttl

    def handle(self, sock):
        try:
            data, addr = self.socket.recvfrom(PACKET_SIZE)
            self.last_update = time.time()
            print('received {} bytes answer from {}'.format(len(data), addr))
        except Exception as e:
            pass
        if data:
            sock.sendto(data, self.q_key[0])
            print('answer to {} with {} bytes'.format(self.q_key[0], len(data)))
            LOOP.remove_reader(self.socket)

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


def create_server(dns):
    # server context
    queries = {}
    # server context

    def server_handler():
        try:
            data, addr = dns.get_sock.recvfrom(PACKET_SIZE)
        except Exception as e:
            pass
        if data is not None:
            print('host {} send {} bytes query'.format(addr, len(data)))
            for remote in dns.remote_dns_list:
                q_key = (addr, remote)
                if q_key not in queries:
                    handler = QueryHandler(remote, TTL)
                    queries[q_key] = handler
                    queries[q_key].q_key = q_key

                    fd = queries[q_key].socket
                    LOOP.add_reader(fd, handler.handle, dns.sock)
                POOL.submit(queries[q_key].sendto, data, (remote, 53))

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
    dns = DNS(bind=LOCAL_DNS, dns_list=DNS_LIST)
    LOOP.add_reader(dns.get_sock, create_server(dns))
    LOOP.run_forever()

if __name__ == '__main__':
    main()
