import socket
from typing import Final

LOCALHOST: Final = "127.0.0.1"
TCP_PORT: Final = 4444


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LOCALHOST, TCP_PORT))
    s.listen()

    while True:
        conn, addr = s.accept()

        with conn:
            print('Connected by', addr)

            buffer = bytes()

            while True:
                buffer += conn.recv(1024)

                parts = buffer.split(b"~~~", 3)

                if len(parts) < 4:
                    continue

                ip_address = parts[0].decode()
                port = parts[1].decode()
                length = int(parts[2].decode())
                rest = parts[3]

                if len(rest) < length:
                    continue

                data = rest[:length]
                buffer = rest[length:]

                data += b" ... hi lol\n\n"

                conn.sendall(f"{ip_address}~~~{port}~~~{len(data)}~~~".encode() + data)