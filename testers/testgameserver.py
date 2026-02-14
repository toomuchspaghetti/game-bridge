import socket
from typing import Final, Optional
from threading import Thread
from time import sleep
from datetime import datetime

LOCALHOST: Final = "127.0.0.1"
UDP_PORT: Final = 5000

reset: bool = False
ping_id: int = 0

def ping_thread_target(socket: socket.socket, connections: list[tuple[str, int]]):
    global reset
    global ping_id
    
    reset = False

    while not reset:
        sleep(3)
        ping_id += 1
        for connection in connections:
            socket.sendto(f"ping... ({ping_id}), ({datetime.now().second})\n".encode(), connection)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((LOCALHOST, UDP_PORT))

    connections: list[tuple[str, int]] = []
    thread: Optional[Thread] = None

    while True:
        data, addr = s.recvfrom(1024)
        data = b"INCOMING ECHO ... " + data + b" ... END OF ECHO\n\n"

        s.sendto(data, addr)

        if addr not in connections:
            connections.append(addr)
            reset = True
            if thread != None:
                thread.join()
            thread = Thread(target=ping_thread_target, args=[s, connections])
            thread.start()
        