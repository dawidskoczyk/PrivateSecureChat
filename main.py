import base64
import socket
import threading
import tkinter as tk
from datetime import time
from tkinter import scrolledtext, messagebox
import json
import queue
import random

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_der_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption
)
from pyDH import DiffieHellman
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import threading
import time
import binascii
class ChatClient:
    def __init__(self, host, port):
        self.decrypted_message1 = " "
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.dh_key_received = threading.Event()
        self.public_keys = {} #tablica kluczy publicznych rsa innych klientów, z którymi się komunikowaliśmy
        self.public_keys_dh = {} #tablica kluczy publicznych diffiego hellmana innych klientów, z którymi się komunikowaliśmy
        self.gui_done = False
        self.running = True
        self.generate_keys() #aes
        self.generate_dh_keys() #dh
        self.nickname = f"User{random.randint(1000, 9999)}"
        self.sock.send(f"NICK:{self.nickname}\n".encode('utf-8'))
        self.decrypt_message1_dh = " "

        self.keys_sent = False  # Nowa flaga do śledzenia, czy klucze zostały wysłane
        # self.sock.send(f"keys:{self.nickname}:{self.private_key}:{self.public_key}\n".encode('utf-8'))

        self.gui_queue = queue.Queue()

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

    def get_public_key(self, recipient):
        self.sock.send(f"GET_PUBLIC_KEY:{recipient}".encode('utf-8'))

    def get_dh_public_key(self, recipient):
        self.sock.send(f"GET_DH_PUBLIC_KEY:{recipient}".encode('utf-8'))

    def gui_loop(self):
        self.win = tk.Tk()
        self.win.title(f"Chat Client - {self.nickname}")
        self.win.configure(bg="lightgray")

        self.name_label = tk.Label(self.win, text=f"Twoja nazwa: {self.nickname}", bg="lightgray",
                                   font=("Arial", 14, "bold"))
        self.name_label.pack(padx=20, pady=10)

        self.chat_label = tk.Label(self.win, text="Chat:", bg="lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')

        self.msg_label = tk.Label(self.win, text="Wiadomość:", bg="lightgray")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tk.Text(self.win, height=3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tk.Button(self.win, text="Wyślij", command=self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.client_list_label = tk.Label(self.win, text="Wybierz odbiorcę (lub nikogo dla wiadomości do wszystkich):",
                                          bg="lightgray")
        self.client_list_label.config(font=("Arial", 12))
        self.client_list_label.pack(padx=20, pady=5)

        self.client_listbox = tk.Listbox(self.win, selectmode=tk.SINGLE)
        self.client_listbox.pack(padx=20, pady=5)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        self.win.after(100, self.process_gui_queue)
        self.win.mainloop()

    def encrypt_message(self, message, public_key_pem):
        message_hash = hashlib.sha256(message.encode()).digest()

        public_key = load_pem_public_key(public_key_pem.encode())

        # Sprawdź rozmiar klucza
        if public_key.key_size > 2048:
            print("Klucz rsa jest zbyt duży. Maksymalny dozwolony rozmiar to 2048 bitów.") #korzystam z klucza rsa długości 2048 bitów i sprawdzam czy został wygenerowany poprawny
        else:
            print("długosc: klucza publicznego rsa" + str(public_key.key_size) )
        encrypted = public_key.encrypt(
            message_hash, #wiadomość shashowana
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), #parametry
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("długosc: zaszyfrowanego rsa razy dwa bo hex" + str(len(encrypted.hex())))
        return encrypted.hex()

    def encrypt_message_dh(self, message, aes_key):
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        iv = cipher.iv
        ct = iv + ct_bytes
        print(f"Zaszyfrowana wiadomość aes: {ct.hex()}")
        return ct

    def send_encrypted_message_dh(self, recipient,sender, message):
        shared_secret = self.calculate_shared_key(recipient) #obliczamy klucz wspólny na podstawie klucza publicznego odbiorcy
        if shared_secret:
            aes_key = self.generate_aes_key(shared_secret) #generujemy klucz aby pasował do biblioteki
            encrypted_message = self.encrypt_message_dh(message, aes_key) #szyfrujemy wiadomość kluczem aesa
            self.sock.send(f"PM_DH:{recipient}:{sender}:{encrypted_message.hex()}\n".encode('utf-8'))
            print(f"Wysłano zaszyfrowaną aes wiadomość do {recipient}")
        else:
            print(f"Nie można wysłać zaszyfrowanej aes wiadomości do {recipient}")

    def decrypt_message(self, encrypted_content, private_key):
        try:
            # Próba dekodowania z hex
            try:
                encrypted_bytes = binascii.unhexlify(encrypted_content)
                print("hex ne wejściu rsa")
            except binascii.Error:
                # Jeśli nie jest hex, spróbuj base64
                try:
                    print("base64")
                    encrypted_bytes = base64.b64decode(encrypted_content)
                    #encrypted_bytes = encrypted_bytes[:256]
                except base64.binascii.Error:
                    # Jeśli nie jest base64, użyj jako surowych bajtów
                    print("bajty")
                    encrypted_bytes = encrypted_content.encode() if isinstance(encrypted_content,str) \
                        else encrypted_content

            print(f"Długość zaszyfrowanej wiadomości rsa: {len(encrypted_bytes)} bajtów")
            print(f"Rozmiar klucza rsa: {private_key.key_size // 8} bajtów")

            decrypted = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.hex()
        except Exception as e:
            raise ValueError(f"Błąd podczas odszyfrowywania rsa: {str(e)}")



    def calculate_shared_key(self, recipient):
        if recipient in self.public_keys_dh:
            recipient_public_key = int(self.public_keys_dh[recipient]) #bierzemy klucz publiczny odbiorcy
            shared_secret = self.dh.gen_shared_key(recipient_public_key) #obliczamy wspólny klucz
            print(f"Wyliczono wspólny klucz dh dla {recipient}: {shared_secret}")
            return shared_secret
        else:
            print(f"Brak klucza publicznego DH dla {recipient}")
            return None

    def generate_aes_key(self, shared_secret):
        aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
        print(f"Wygenerowano klucz AES: {aes_key.hex()}")
        return aes_key

    def decrypt_message_dh(self, encrypted_content, aes_key):
        try:
            print(f"Typ encrypted_content aes: {type(encrypted_content)}")
            print(f"Pierwsze 20 znaków encrypted_content aes: {encrypted_content[:20]}")

            # Konwertuje encrypted_content na bajty, jeśli jest stringiem
            if isinstance(encrypted_content, str):
                try:
                    # Próba konwersji z hex
                    encrypted_content = bytes.fromhex(encrypted_content)
                    print("konwersja z hexa do bitów do dalszej dekrypcji aes")
                except ValueError:
                    # Jeśli nie jest hex, próbuje zakodować jako UTF-8
                    encrypted_content = encrypted_content.encode('utf-8')

            # Upewniam się, że aes_key jest również w formie bajtów
            if isinstance(aes_key, str):
                aes_key = aes_key.encode('utf-8')

            # Upewniam się, że klucz AES ma odpowiednią długość (32 bajty dla AES-256)
            aes_key = aes_key[:32].ljust(32, b'\0')

            iv = encrypted_content[:16] #wektor inicjujący 128 bitowy
            ciphertext = encrypted_content[16:]

            # Tworzy nowy obiekt szyfru AES w trybie CBC z podanym kluczem i wektorem inicjalizacyjnym
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            # Deszyfruje tekst zaszyfrowany używając szyfru, a następnie usuwa padding, aby uzyskać oryginalny tekst jawny
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Błąd podczas deszyfrowania aes: {e}")
            print(f"Długość encrypted_content aes: {len(encrypted_content)}")
            print(f"Długość aes_key : {len(aes_key)}")
            return None

    def process_gui_queue(self):
        try:
            while True:
                function, args, kwargs = self.gui_queue.get_nowait()
                function(*args, **kwargs)
                self.gui_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.win.after(100, self.process_gui_queue)

    def write(self):
        message = self.input_area.get('1.0', 'end').strip()
        if message:
            selected_indices = self.client_listbox.curselection()
            if selected_indices:
                recipient = self.client_listbox.get(selected_indices[0])
                if recipient not in self.public_keys: #chodzi o rsa
                    self.get_public_key(recipient)
                    #pobieranie klucza rsa z serwera jeśli nie ma go w lokalnej tablicy kluczy rsa klienta
                    self.update_chat("twoja pierwsza wiadomość")
                # przypisanie klucza do zmiennej
                public_key = self.public_keys[recipient]
                if recipient not in self.public_keys_dh: # to samo dla dh pobieramy klucz z serwera jeśli go nie ma klient
                    self.get_dh_public_key(recipient)
                    max_wait_time = 5  # Maksymalny czas oczekiwania w sekundach
                    wait_interval = 0.5  # Sprawdzamy co pół sekundy
                    total_waited = 0

                    while recipient not in self.public_keys_dh and total_waited < max_wait_time:
                        time.sleep(wait_interval)
                        total_waited += wait_interval

                    if recipient not in self.public_keys_dh:
                        print(f"Nie udało się otrzymać klucza DH dla {recipient} w czasie {max_wait_time} sekund.")
                        return  # Przerywamy, jeśli nie udało się otrzymać klucza
                #może dodać tu chwile czekania? ale nie trzeba
                #hash message
                #message_hash = hashlib.sha256(message.encode()).digest()
                sender = self.nickname
                self.send_encrypted_message_dh(recipient,sender, message) #wysyłanie zaszyfrowanej wiadomości aes
                # hash message sha-256
                encrypted_message = self.encrypt_message(message, public_key) #RSA przesyłanie do funkcji wiadomości do shaszowania i klucz publiczny odbiorcy

                #w tym miejscu wysyłam zaszyfrowaną wiadomość
                self.sock.send(f"PM:{recipient}:{sender}:{encrypted_message}\n".encode('utf-8'))
                self.update_chat(f"Ty do {recipient}: {message}")
            else:
                self.sock.send(f"BROADCAST:{message}\n".encode('utf-8'))
                self.update_chat(f"Ty (do wszystkich): {message}")
            self.input_area.delete('1.0', 'end')

    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    def send_keys(self): #RSA
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Wysyłamy tylko klucz publiczny
        self.sock.send(f"KEYS:{self.nickname}:{public_key_pem}\n".encode('utf-8'))
        print(f"Wysłano klucz publiczny rsa dla {self.nickname}")

    def send_dh_key(self): #DH
        # Zakładamy, że self.dh_public_key już istnieje po wywołaniu generate_dh_keys()
        dh_public_key_str = str(self.dh_public_key)

        # Wysyłamy klucz publiczny DH
        self.sock.send(f"DH_KEY:{self.nickname}:{dh_public_key_str}\n".encode('utf-8'))
        print(f"Wysłano klucz publiczny DH dla {self.nickname}")

    def receive(self):
        while self.running:
            try:
                message = self.sock.recv(1024).decode('utf-8')
                if not message:
                    self.gui_queue.put((self.show_connection_lost_message, (), {}))
                    break

                if message.startswith("CLIENT_LIST:"):
                    self.gui_queue.put((self.update_client_list, (message[12:],), {}))
                    if not self.keys_sent:
                        self.send_keys()
                        self.send_dh_key()
                        self.keys_sent = True
                elif message.startswith("PUBLIC_KEY:"):
                    _, recipient, key = message.split(":", 2)
                    self.public_keys[recipient] = key
                    print(f"Klucz publiczny rsa dla {recipient} został zapisany na kliencie. "+ self.public_keys[recipient])
                elif message.startswith("DH_PUBLIC_KEY:"):
                    _, recipient, key = message.split(":", 2)
                    self.public_keys_dh[recipient] = key
                    print(f"Klucz publiczny DH dla {recipient} został zapisany na kliencie. "+ self.public_keys_dh[recipient])
                    #shared = self.calculate_shared_key(recipient)
                    #self.generate_aes_key(shared)
                elif message.startswith("ENCRYPTEDGET:"):
                    _, recipient, sender ,encrypted_content = message.split(":", 3)
                    print("otrzymana zaszyfrowana wiadomość rsa długość"+ str(len(encrypted_content)))
                    #tutaj chce odszyfrować i wyświetlić wiadomość
                    try:
                        print(str(len(encrypted_content)) + " długość wiadomości Rsa przed odszyfrowaniem")
                        # Zakładamy, że masz dostęp do swojego klucza prywatnego
                        #encrypted_content1 = base64.b64decode(encrypted_content)
                        decrypted_message = self.decrypt_message(encrypted_content, self.private_key)
                        self.decrypted_message1 = decrypted_message
                        decrypted_message1_dh_hash = hashlib.sha256(self.decrypted_message1_dh.encode()).digest()
                        print("wynik rsa: " + self.decrypted_message1)
                        print("hash wiadomości po aes: " + decrypted_message1_dh_hash.hex())
                        if (self.decrypted_message1 == decrypted_message1_dh_hash.hex()):
                            print("to samo")
                            self.update_chat(f"Odszyfrowana wiadomość od {sender}: {self.decrypted_message1_dh}")
                        else:
                            print("coś nie tak" + decrypted_message)

                    except Exception as e:
                        self.update_chat(f"Błąd podczas odszyfrowywania wiadomości RSA od : {str(e)}")
                elif message.startswith("ENCRYPTED_DH:"):
                    _, sender, sender_public_key, encrypted_content = message.split(":", 3)
                    print(f"Otrzymano zaszyfrowaną wiadomość aes od {sender}")
                    self.public_keys_dh[sender] = sender_public_key

                    sender_public_key = int(sender_public_key)
                    shared_secret = self.dh.gen_shared_key(sender_public_key)

                    # Wygeneruj klucz AES ze wspólnego sekretu
                    aes_key = self.generate_aes_key(shared_secret)

                    # Odszyfruj wiadomość
                    decrypted_message_dh = self.decrypt_message_dh(encrypted_content, aes_key)
                    self.decrypted_message1_dh = decrypted_message_dh
                    print(f"Odszyfrowana wiadomość aes od {sender}: {decrypted_message_dh}")

                elif message.strip():
                    self.gui_queue.put((self.update_chat, (message,), {}))
            except Exception as e:
                print(f"Błąd w receive: {e}")
                self.gui_queue.put((self.show_connection_lost_message, (), {}))
                break

        print("Zamykanie połączenia...")
        self.sock.close()

    def update_chat(self, message):
        self.text_area.config(state='normal')
        self.text_area.insert('end', message + '\n')
        self.text_area.yview('end')
        self.text_area.config(state='disabled')

    def update_client_list(self, client_list_json):
        try:
            client_list = json.loads(client_list_json)
            self.client_listbox.delete(0, tk.END)
            for client in client_list:
                if client != self.nickname:
                    self.client_listbox.insert(tk.END, client)
        except json.JSONDecodeError:
            print(f"Błąd dekodowania JSON: {client_list_json}")

    def show_connection_lost_message(self):
        messagebox.showerror("Błąd połączenia", "Utracono połączenie z serwerem.")
        self.stop()

    def update_nickname(self, new_nickname):
        self.nickname = new_nickname
        self.name_label.config(text=f"Twoja nazwa: {self.nickname}")
        self.win.title(f"Chat Client - {self.nickname}")

    def generate_keys(self):
        # Generowanie pary kluczy
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Serializacja klucza publicznego do formatu PEM
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(self.private_key)
        print(self.public_key)

    def generate_dh_keys(self):
        # Tworzenie obiektu Diffie-Hellman
        self.dh = DiffieHellman()

        # Generowanie klucza publicznego
        self.dh_public_key = self.dh.gen_public_key()

        print(f"Klucz publiczny DH: {self.dh_public_key}")

    def generate_shared_secret(self, server_public_key):
        self.shared_secret = self.dh.gen_shared_key(server_public_key)
        print(f"Wygenerowany współdzielony sekret: {self.shared_secret}")
        return self.shared_secret

if __name__ == "__main__":
    client = ChatClient('192.168.71.20', 5557)