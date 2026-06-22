import socket

UDP_IP = "0.0.0.0"
UDP_PORT = 162

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on UDP/{UDP_PORT}...")

while True:
    data, addr = sock.recvfrom(65535)
    print(f"\nReceived {len(data)} bytes from {addr}")
    print(data.hex())