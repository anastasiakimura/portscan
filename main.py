import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from struct import pack
import socket

PACKET = b'\x13' + b'\x00' * 39 + b'\x6f\x89\xe9\x1a\xb6\xd5\x3b\xd3'

MAX_PORT = 65535


class Args:
    def __init__(self):
        self.host, self.start, self.end, self.tcp, self.udp = self._parse_args()

    @staticmethod
    def _parse_args() -> tuple[str, int, int, bool, bool]:
        parser = argparse.ArgumentParser(description='TCP port scanner.')
        parser.add_argument('-p', '--ports', type=int, nargs=2, dest='ports',
                            help='port or range of ports example: 1 100')
        parser.add_argument('--host', type=str, dest='host',
                            default='localhost', help='host to scan')
        parser.add_argument('-t', default=False, dest='tcp', help='scan tcp', action=argparse.BooleanOptionalAction)
        parser.add_argument('-u', default=False, dest='udp', help='scan udp', action=argparse.BooleanOptionalAction)
        args = parser.parse_args()
        try:
            start, end = args.ports[0], args.ports[1]
        except ValueError:
            print('Port number must be integer')
            sys.exit()
        if end > MAX_PORT:
            print('Port numbers must be less than 65535')
            sys.exit()
        if start > end:
            print('Invalid arguments')
            sys.exit()
        try:
            socket.gethostbyname(args.host)
        except socket.gaierror:
            print(f'Invalid host {args.host}')
            sys.exit()
        if not args.tcp and not args.udp:
            print('You forget about -t or -u, i dont know what i should scan')
            sys.exit()
        return args.host, start, end, args.tcp, args.udp


class DNS:
    @staticmethod
    def is_dns(packet: bytes) -> bool:
        transaction_id = PACKET[:2]
        return transaction_id in packet


class SNTP:
    @staticmethod
    def is_sntp(packet: bytes) -> bool:
        transmit_timestamp = PACKET[-8:]
        origin_timestamp = packet[24:32]
        is_packet_from_server = 7 & packet[0] == 4
        return len(packet) >= 48 and is_packet_from_server and origin_timestamp == transmit_timestamp


class POP3:
    @staticmethod
    def is_pop3(packet: bytes) -> bool:
        return packet.startswith(b'+')


class HTTP:
    @staticmethod
    def is_http(packet: bytes) -> bool:
        return b'HTTP' in packet


class SMTP:
    @staticmethod
    def is_smtp(packet: bytes) -> bool:
        return packet[:3].isdigit()


class Scanner:
    _PROTOCOL_DEFINER = {
        'SMTP': lambda packet: SMTP.is_smtp(packet),
        'DNS': lambda packet: DNS.is_dns(packet),
        'POP3': lambda packet: POP3.is_pop3(packet),
        'HTTP': lambda packet: HTTP.is_http(packet),
        'SNTP': lambda packet: SNTP.is_sntp(packet)
    }

    def __init__(self, host: str):
        self._host = host

    def tcp_port(self, port: int) -> str:
        socket.setdefaulttimeout(0.5)
        result = ''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
            try:
                scanner.connect((self._host, port))
                result = f'TCP {port}'
            except (socket.timeout, TimeoutError, OSError):
                pass
            try:
                scanner.send(pack('!H', len(PACKET)) + PACKET)
                data = scanner.recv(1024)
                result += f' {self._check(data)}'
            except socket.error:
                pass
        return result

    def udp_port(self, port: int) -> str:
        socket.setdefaulttimeout(3)
        result = ''
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as scanner:
            try:
                scanner.sendto(PACKET, (self._host, port))
                data, _ = scanner.recvfrom(1024)
                result = f'UDP {port} {self._check(data)}'
            except socket.error:
                pass
        return result

    def _check(self, data: bytes) -> str:
        for protocol, checker in self._PROTOCOL_DEFINER.items():
            if checker(data):
                return protocol
        return ''


def main(host: str, start: int, end: int, tcp: bool, udp: bool):
    scanner = Scanner(host)
    with ThreadPoolExecutor(max_workers=300) as pool:
        for port in range(start, end + 1):
            pool.submit(execute, scanner, port, tcp, udp)


def execute(scanner: Scanner, port: int, tcp: bool, udp: bool):
    if tcp:
        show(scanner.tcp_port(port))
    if udp:
        show(scanner.udp_port(port))


def show(result: str):
    if result:
        print(result)


if __name__ == "__main__":
    args = Args()
    main(args.host, args.start, args.end, args.tcp, args.udp)