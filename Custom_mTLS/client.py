import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import datetime


with open("client_cert.pem", "rb") as f:
    client_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
with open("client_key.pem", "rb") as f:
    client_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

client_public_key = client_cert.public_key()

def verify_certificate(cert):
    now = datetime.datetime.now(datetime.UTC)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise ValueError("Сертификат просрочен")


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))
print("Подключено к серверу")


server_cert_len = int.from_bytes(client_socket.recv(4), 'big')
server_cert_pem = client_socket.recv(server_cert_len)
server_cert = x509.load_pem_x509_certificate(server_cert_pem, backend=default_backend())


verify_certificate(server_cert)
server_public_key = server_cert.public_key()


client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
client_socket.sendall(len(client_cert_pem).to_bytes(4, 'big'))
client_socket.sendall(client_cert_pem)


def encrypt_message(data, public_key):
    return public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_data, private_key):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

def send_encrypted(sock, data, public_key):
    encrypted = encrypt_message(data, public_key)
    sock.sendall(len(encrypted).to_bytes(4, 'big'))
    sock.sendall(encrypted)

def recv_encrypted(sock, private_key):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    encrypted_data = sock.recv(msg_len)
    return decrypt_message(encrypted_data, private_key)


while True:
    msg = input("Клиент: ")
    if msg.lower() == 'exit':
        break
    send_encrypted(client_socket, msg, server_public_key)
    
    reply = recv_encrypted(client_socket, client_private_key)
    if reply is None:
        print("Сервер отключился.")
        break
    print(f"Сервер: {reply}")

client_socket.close()