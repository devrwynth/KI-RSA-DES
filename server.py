import socket
import threading

HOST = '192.168.0.101'  #IP local server
PORT = 26801      
client1 = 0
client2 = 0


def handle_client(conn, addr):
    global client1
    global client2
    print(f"Connected by {addr}")
    role = None

    try:
        while True:
            data = conn.recv(1024)

            message = data.decode('utf-8')
            if message == "request":
                if client1 == 0:
                    client1 = conn
                    conn.sendall("client1".encode('utf-8'))
                    role = "client1"
                    
                elif client2 == 0:
                    client2 = conn
                    conn.sendall("client2".encode('utf-8'))
                    role = "client2"
                    
                else:
                    conn.sendall("full".encode('utf-8'))
            else:
            
                # Relay the message to all other connected clients
                relay_target = None
                if role == "client2":
                    relay_target = client1
                elif role == "client1":
                    relay_target = client2

                relay_target.sendall(message.encode('utf-8'))

    except ConnectionResetError:
        print(f"Client {addr} disconnected unexpectedly.")
    finally:
        print(f"Client {addr} disconnected.")
        conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        s.close()


                