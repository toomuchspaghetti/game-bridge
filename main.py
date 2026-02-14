from typing import Optional, Final
from ipaddress import IPv4Address
import struct

GAMER_ADDRESS_FORMAT: Final = "!IH"
NUMBER_OF_BYTES_IN_GAMER_ADDRESS: Final = 6

def get_packet(gamer_ip_address: IPv4Address, gamer_port: int, data: bytes) -> bytes:
    gamer_address = struct.pack(GAMER_ADDRESS_FORMAT, int(gamer_ip_address), gamer_port)
    return gamer_address + f"~{len(data)}~".encode() + data

def decode_packet(buffer: bytes) -> Optional[tuple[tuple[IPv4Address, int, bytes], bytes]]:
    try:
        gamer_address = struct.unpack(GAMER_ADDRESS_FORMAT, buffer[:NUMBER_OF_BYTES_IN_GAMER_ADDRESS])
    
        ip_address = IPv4Address(gamer_address[0])
        port = gamer_address[1]
    
        length_and_rest = buffer[NUMBER_OF_BYTES_IN_GAMER_ADDRESS:]
        parts = length_and_rest.split(b"~", 2)

        length = int(parts[1])
        rest = parts[2]
    except Exception:
        return
    
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
    EVERYWHERE: Final = "0.0.0.0"

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

                                while (decoded_packet_and_buffer := decode_packet(packet_buffer)) != None:
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
                                        ip_address, port_as_string = new_gamer_address.split(":")
                                        port = int(port_as_string)

                                        data = game_socket.recv(4096)

                                        packet_connection.sendall(get_packet(IPv4Address(ip_address), port, data))

                                        break
                except KeyboardInterrupt:
                    pass
                except Exception:
                    import traceback
                    traceback.print_exc()

                print("closing game sockets...")

                for game_socket in game_sockets_by_gamer_address.values():
                    game_socket.close()
    else:
        try:
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
                        listening_socket.bind((EVERYWHERE, udp_port))
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

                                ip_address = IPv4Address(addr[0])
                                port: int = addr[1]

                                transmission_socket.sendall(get_packet(ip_address, port, data))
                                #print(addr)
                            elif ready_socket is transmission_socket:
                                transmission_buffer += transmission_socket.recv(1024)

                                while (decoded_packet_and_buffer := decode_packet(transmission_buffer)) != None:
                                    decoded_packet, transmission_buffer = decoded_packet_and_buffer
                                    ip_address, port, data = decoded_packet

                                    listening_socket.sendto(data, (str(ip_address), port))
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()