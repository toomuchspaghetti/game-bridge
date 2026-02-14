import socket
from typing import Final

LOCALHOST: Final = "127.0.0.1"
UDP_PORT: Final = 5000


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((LOCALHOST, UDP_PORT))

    while True:
        data, addr = s.recvfrom(1024)
        data = b"INCOMING ECHO ... " + data + b" ... END OF ECHO\n\n"

        s.sendto(data, addr)
        