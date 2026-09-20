import socket
import time

SERVER_IP = '10.0.2.15'
SERVER_PORT = 20000
TIMEOUT = 2.0  # 接收超时时间（秒）

def main():
    # 创建 UDP 套接字 (IPv4, UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    print(f"[*] Target UDP Server: {SERVER_IP}:{SERVER_PORT}")
    print("[*] Input text to send, or type 'q' / 'exit' to quit.\n")

    try:
        while True:
            message = input("> ")
            if message.strip().lower() in ('q', 'exit'):
                print("Exiting...")
                break
            if not message:
                continue

            # 1. 记录发送时间
            start_time = time.perf_counter()

            # 2. 发送数据
            sock.sendto(message.encode('utf-8'), (SERVER_IP, SERVER_PORT))

            try:
                # 3. 接收 Echo 回包 (缓冲区设为 2048 字节)
                data, server_addr = sock.recvfrom(2048)
                
                # 4. 计算 RTT (毫秒)
                rtt_ms = (time.perf_counter() - start_time) * 1000

                print(f"  [<-] Echo from {server_addr[0]}:{server_addr[1]} "
                      f"({len(data)} bytes) | RTT: {rtt_ms:.2f} ms")
                print(f"  [<-] Payload: {data.decode('utf-8', errors='replace')}\n")

            except socket.timeout:
                print("  [X] Request timed out (Server did not respond)\n")

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        sock.close()

if __name__ == '__main__':
    main()