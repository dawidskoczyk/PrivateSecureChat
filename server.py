import socket
import threading
import json

clients = {}  # Zmiana z listy na słownik, gdzie kluczem jest nickname
publicKeys ={} #RSA
dh_public_keys = {} #DH
def broadcast(message, sender=None):
    for nick, client in clients.items():
        if client != sender:
            try:
                client.send(message.encode('utf-8') + b'\n')
            except:
                remove_client(nick)

def handle_client(client):
    while True:
        try:
            message = client.recv(1024).decode('utf-8').strip()
            if message.startswith("NICK:"):
                nickname = message[5:]
                clients[nickname] = client
                broadcast_client_list()
            elif message.startswith("GET_PUBLIC_KEY:"):
                _, recipient = message.split(":", 1)
                if recipient in publicKeys:
                    print(f"PUBLIC_KEY rsa:{recipient}:{publicKeys[recipient]}")
                    client.send(f"PUBLIC_KEY:{recipient}:{publicKeys[recipient]}".encode('utf-8'))
                else:
                    print(f"PUBLIC_KEY:{recipient} brak klucza")
                    #client.send(f"ERROR:Brak klucza publicznego dla {recipient}".encode('utf-8'))
            elif message.startswith("GET_DH_PUBLIC_KEY:"):
                _, recipient = message.split(":", 1)
                if recipient in dh_public_keys:
                    print(f"PUBLIC_KEY dh:{recipient}:{dh_public_keys[recipient]}")
                    client.send(f"DH_PUBLIC_KEY:{recipient}:{dh_public_keys[recipient]}".encode('utf-8'))
                else:
                    print(f"PUBLIC_KEY:{recipient} brak klucza")
                    # client.send(f"ERROR:Brak klucza publicznego dla {recipient}".encode('utf-8'))
            elif message.startswith("DH_KEY:"):
                _, owner, content  = message.split(":", 2)
                dh_public_keys[owner] = content
                if owner in dh_public_keys:
                    print(f"DH_KEY:{owner}:{content}")
                    #client.send(f"DH_KEY:{recipient}:{dh_key}".encode('utf-8'))
                else:
                    print(f"DH_KEY:{recipient} brak klucza")
                    client.send(f"ERROR:Brak klucza DH dla {recipient}".encode('utf-8'))
            elif message.startswith("PM:"):
                _, recipient, sender, content = message.split(":", 3)
                print(recipient+ "odbiorca +" + "wiadomosc rsa"+ content)
                if recipient in clients:
                    print("Dlugość zaszyfrowanej wiadomości rsa przed wysłaniem do odbiorcy: "+ str(len(content)))
                    clients[recipient].send(f"ENCRYPTEDGET:{recipient}:{sender}:{content}".encode('utf-8'))
            elif message.startswith("PM_DH:"):
                _, recipient, sender, content = message.split(":", 3)
                print(recipient + "odbiorca +" + "wiadomosc aes"+ content)
                if recipient in clients and sender in dh_public_keys:
                    sender_public_key = dh_public_keys[sender]
                    clients[recipient].send(f"ENCRYPTED_DH:{sender}:{sender_public_key}:{content}\n".encode('utf-8'))
                    print(f"Wysłano zaszyfrowaną wiadomość do {recipient} wraz z kluczem publicznym nadawcy aes")
                elif recipient not in clients:
                    print(f"Nie można dostarczyć wiadomości. Odbiorca {recipient} nie jest połączony.")
                elif sender not in dh_public_keys:
                    print(f"Brak klucza publicznego DH dla nadawcy {sender}")
            elif message.startswith("BROADCAST:"):
                content = message[10:]
                broadcast(f"{nickname}: {content}", client)
            elif message.startswith("KEYS:"):
                _, ownerkp, kp = message.split(":", 2)
                print("dostałem od " + ownerkp + " klucz rsa "+ kp)
                publicKeys[ownerkp] = kp
                print(f"Dodano klucz publiczny rsa dla klienta {len(publicKeys)} do słownika publicKeys")
                print("Zawartość słownika publicKeys rsa:")
                [print(f" {key[:30]}...") for  key in publicKeys.items()]
            else:
                broadcast(f"{nickname}: {message}", client)
        except Exception as e:
            print(f"Błąd w obsłudze klienta: {e}")
            remove_client(nickname)
            break

def broadcast_client_list():
    client_list = json.dumps(list(clients.keys()))
    broadcast(f"CLIENT_LIST:{client_list}")

def remove_client(nickname):
    if nickname in clients:
        client = clients.pop(nickname)
        client.close()
        broadcast(f"{nickname} opuścił czat!")
        broadcast_client_list()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('192.168.71.20', 5557))
    server.listen()

    print("Serwer nasłuchuje...")

    while True:
        try:
            client, address = server.accept()
            print(f"Połączono z {str(address)}")

            thread = threading.Thread(target=handle_client, args=(client,))
            thread.start()

        except Exception as e:
            print(f"Błąd w akceptowaniu połączenia: {e}")

if __name__ == "__main__":
    start_server()