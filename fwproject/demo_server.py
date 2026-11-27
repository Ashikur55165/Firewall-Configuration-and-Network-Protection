#!/usr/bin/env python3
"""Non-privileged demo services used to test firewall allow/block rules."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading

class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            'Firewall Project TCP demo service is reachable.\n'
            f'Path: {self.path}\n'
            f'Client address: {self.client_address[0]}\n'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print('[TCP demo] ' + (fmt % args), flush=True)


def udp_echo():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 9999))
    print('[UDP demo] Listening on 0.0.0.0:9999/udp', flush=True)
    while True:
        data, address = sock.recvfrom(2048)
        print(f'[UDP demo] Received {len(data)} bytes from {address[0]}:{address[1]}', flush=True)
        sock.sendto(b'Firewall Project UDP demo received: ' + data[:1024], address)


if __name__ == '__main__':
    threading.Thread(target=udp_echo, daemon=True).start()
    print('[TCP demo] Listening on 0.0.0.0:8080/tcp', flush=True)
    ThreadingHTTPServer(('0.0.0.0', 8080), DemoHandler).serve_forever()
