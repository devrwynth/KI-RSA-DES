import socket
import DES
import threading
import sys

PUBLIC_KEY_AUTHORITY_IP = '139.228.160.209'  
SERVER_IP = '139.228.160.209'
PKA_PORT = 26800
SERVER_PORT = 26801         
CLIENT_NAME = input('client name: ')
TARGET_CLIENT = input('target client name: ')
target_public_key = None

#generate private and public RSA keys
publickey = input("public key: ") # placeholder

# register public key to PKA
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((PUBLIC_KEY_AUTHORITY_IP, PKA_PORT))

    s.sendall(f'new,{CLIENT_NAME},{publickey}'.encode('utf-8'))

    data = s.recv(1024)
    reply = data.decode('utf-8')
    print(reply)

#loop request public key of target client until received
try_again = True
print("Getting target client public key...")
while try_again:
    reply = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((PUBLIC_KEY_AUTHORITY_IP, PKA_PORT))

        s.sendall(f'request,{TARGET_CLIENT},{publickey}'.encode('utf-8'))

        data = s.recv(1024)
        reply = data.decode('utf-8')
        
    if (reply != "not registered"):
        target_public_key = reply
        try_again = False
    else:
        try_again_prompt = input("Target public key not registered, Try again? (Y/N): ")
        try_again = try_again_prompt != "N"

# received target key
print(f"Target public key: {target_public_key}")


#receive message thread
def receive_messages(s):
    try:
        while True:
            data = s.recv(1024)
            if not data:
                break
            DES_rkb_rev = DES.generate_keys(DES_key)[::-1]
            decrypted_message = DES.des_decrypt_dynamic(data.decode('utf-8'), DES_rkb_rev)
            sys.stdout.write('\r' + ' ' * 80 + '\r')
            print(f"Received from server: {data.decode('utf-8')}")
            print(f"Decrypted: {decrypted_message}")
            print("(quit with \"exit\") message: ")
    except ConnectionResetError:
        print("Server disconnected.")
    except OSError:
        pass # Socket closed
    finally:
        print("Stopped recieveing")

#connect to server

#if assigned client2
#generate DES session key
#send encrypted (with RSA, pc2 public key) session key (DES) to server:target client
#start chatting with message encrypted using DES key

#if assigned client1
#wait for DES session key
#receive RSA-Encrypted DES key and decrypt using RSA private key 
#start chatting with message encrypted using DES key



role = None
DES_key = None
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, SERVER_PORT))

    #plaintext = input("Masukkan plaintext (panjang berapapun): ")

    s.sendall('request'.encode('utf-8'))

    data = s.recv(1024)
    reply = data.decode('utf-8')
    role = reply
    print(role)
    if (role == 'client2'):
        #generate DES key
        # Kunci DES di-padding/truncation (seperti di kode asli)
        DES_key_input = "12345678"
        key_bytes = DES_key_input.encode('utf-8')
        if len(key_bytes) != 8:
            print(f"Key di-adjust ke 8 byte: {len(key_bytes)} byte.")
            key_bytes = key_bytes.ljust(8, b'\x00')[:8]
            
        original_key_hex = key_bytes.hex().upper()
        generated_DES_Key = original_key_hex

        DES_key = generated_DES_Key
        DES_rkb = DES.generate_keys(DES_key)
        DES_key_encrypted = DES_key # placeholder RSA encryption
        #send DES key to server and so the other client
        s.sendall(DES_key_encrypted.encode('utf-8'))
        print("Chatting start")
        receive_thread = threading.Thread(target=receive_messages, args=(s,))
        receive_thread.start()
        typed_message = "placeholder"
        while typed_message != "exit":
            typed_message = input("(quit with \"exit\") message: ")
            encrypted_message = DES.des_encrypt_dynamic(typed_message, DES_rkb)
            s.sendall(encrypted_message.encode('utf-8'))


    
    if (role == 'client1'):
        print("Awaiting other client...")
        while True:
            try:
                #recieve DES key (placeholder)
                mes = s.recv(1024).decode('utf-8')
                if not mes:
                    continue
                DES_key = mes#[:4] # placeholder RSA decryption
                DES_rkb = DES.generate_keys(DES_key)

                print(f"Received Decrypted DES KEY: {DES_key}")
                break
            except KeyboardInterrupt:
                break
        print("Chatting start")
        receive_thread = threading.Thread(target=receive_messages, args=(s,))
        receive_thread.start()
        typed_message = "placeholder"
        while typed_message != "exit":
            typed_message = input("(quit with \"exit\") message: ")
            encrypted_message = DES.des_encrypt_dynamic(typed_message, DES_rkb)
            s.sendall(encrypted_message.encode('utf-8'))
    