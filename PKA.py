import socket

HOST = '192.168.0.101'  #IP PKA local
PORT = 26800      

def init_keys():
    pass
    #create public and private key

init_keys()

#store client keys
key_database = {}

#start server and listen for key requests
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    message = data.decode('utf-8')
                    request_type, id, public_key = message.split(',')
                    
                    if request_type == 'new':
                        if id in key_database:
                            print(f"Public key with id:{id} has already been registered, overwriting...")
                        key_database.update({id: public_key})
                        conn.sendall("Public key added".encode('utf-8'))
                    elif request_type == 'request':
                        if id in key_database:
                            conn.sendall(key_database[id].encode('utf-8'))
                        else:
                            conn.sendall("not registered".encode('utf-8'))
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        s.close()
                
                