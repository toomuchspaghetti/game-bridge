from typing import Optional, Final

def get_packet(gamer_ip_address: str, gamer_port: int, data: bytes) -> bytes:
    return (f"{gamer_ip_address}~~~{gamer_port}~~~{len(data)}~~~").encode() + data

def decode_packet(buffer: bytes) -> Optional[tuple[tuple[str, int, bytes], bytes]]:
    parts = buffer.split(b"~~~", 3)

    if len(parts) < 4:
        return

    ip_address = parts[0].decode()
    port = int(parts[1].decode())
    length = int(parts[2].decode())
    rest = parts[3]

    if len(rest) < length:
        return

    data = rest[:length]
    buffer = rest[length:]

    return (ip_address, port, data), buffer

def main():
    import argparse

    parser = argparse.ArgumentParser(
                        prog='UDP tunnel',
                        description='Sends UDP packets to a TCP connection (TCP connection not included)',
                        epilog='Good luck')

    parser.add_argument('-P', '--udp-port', required=True, type=int, help="UDP port")
    parser.add_argument('-p', '--tcp-port', required=True, type=int, help="TCP port")
    parser.add_argument('-s', '--server', help="Is this instance connecting to the game server?", action="store_true")

    args = parser.parse_args()

    import socket
    import select

    tcp_port: Final = args.tcp_port
    udp_port: Final = args.udp_port
    server: Final = args.server

    LOCALHOST: Final = "127.0.0.1"

    if server:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as packet_socket:
            packet_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            packet_socket.bind((LOCALHOST, tcp_port))
            packet_socket.listen()

            packet_connection, packet_addr = packet_socket.accept()

            print(f"tcp bridge established with: {packet_addr}")

            with packet_connection:
                packet_buffer = bytes()
                
                game_sockets_by_gamer_address: dict[str, socket.socket] = {}

                try:
                    while True:
                        ready_sockets, _, _ = select.select([packet_connection] + list(game_sockets_by_gamer_address.values()), [], [])
                            
                        for ready_socket in ready_sockets:
                            if ready_socket is packet_connection:
                                packet_buffer += packet_connection.recv(1024)

                                decoded_packet_and_buffer = decode_packet(packet_buffer)

                                if decoded_packet_and_buffer == None:
                                    continue

                                decoded_packet, packet_buffer = decoded_packet_and_buffer
                                ip_address, port, data = decoded_packet

                                gamer_address = f"{ip_address}:{port}"

                                #print(f"{gamer_address} <=== {len(data)}")

                                if gamer_address not in game_sockets_by_gamer_address:
                                    print(f"new socket for {gamer_address}")
                                    new_game_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    new_game_socket.connect((LOCALHOST, udp_port))
                                    game_sockets_by_gamer_address[gamer_address] = new_game_socket

                                game_sockets_by_gamer_address[gamer_address].sendall(data)
                            else:
                                for new_gamer_address, game_socket in game_sockets_by_gamer_address.items():
                                    if game_socket is ready_socket:
                                        ip_address, port = new_gamer_address.split(":")
                                        port = int(port)

                                        data = game_socket.recv(4096)

                                        packet_connection.sendall(get_packet(ip_address, port, data))

                                        break
                except KeyboardInterrupt:
                    pass
                except Exception:
                    import traceback
                    traceback.print_exc()

                for game_socket in game_sockets_by_gamer_address.values():
                    game_socket.close()
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as transmission_socket:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listening_socket:
                transmission_addr = (LOCALHOST, tcp_port)
                try:
                    transmission_socket.connect(transmission_addr)
                except Exception:
                    print(f"cannot connect to tcp bridge. port: {tcp_port}")
                    exit(1)

                print(f"tcp bridge established with: {transmission_addr}")

                try:
                    listening_socket.bind((LOCALHOST, udp_port))
                except Exception:
                    print(f"cannot bind udp socket to port {udp_port}")
                    exit(1)

                transmission_buffer = bytes()

                while True:
                    ready_sockets, _, _ = select.select([transmission_socket, listening_socket], [], [])

                    for ready_socket in ready_sockets:
                        if ready_socket is listening_socket:
                            data, addr = listening_socket.recvfrom(4096)

                            if not data:
                                continue

                            ip_address = addr[0]
                            port = addr[1]

                            transmission_socket.sendall(get_packet(ip_address, port, data))
                            #print(addr)
                        elif ready_socket is transmission_socket:
                            transmission_buffer += transmission_socket.recv(1024)

                            decoded_packet_and_buffer = decode_packet(transmission_buffer)

                            if decoded_packet_and_buffer == None:
                                continue

                            decoded_packet, transmission_buffer = decoded_packet_and_buffer
                            ip_address, port, data = decoded_packet

                            listening_socket.sendto(data, (ip_address, port))
if __name__ == "__main__":
    main()