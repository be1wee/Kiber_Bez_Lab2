import datetime
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


with open("server_cert.pem", "rb") as f:
    server_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
with open("server_key.pem", "rb") as f:
    server_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

server_public_key = server_cert.public_key()


def verify_certificate(cert):
    now = datetime.datetime.now(datetime.UTC)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise ValueError("Сертификат просрочен")
    
    try:
        cert.verify_directly_issued_by(cert)  
    except Exception:
        
        pass


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Сервер запущен")

conn, addr = server_socket.accept()
print(f"Подключен клиент {addr}")


server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
conn.sendall(len(server_cert_pem).to_bytes(4, 'big'))
conn.sendall(server_cert_pem)


client_cert_len = int.from_bytes(conn.recv(4), 'big')
client_cert_pem = conn.recv(client_cert_len)
client_cert = x509.load_pem_x509_certificate(client_cert_pem, backend=default_backend())


verify_certificate(client_cert)
client_public_key = client_cert.public_key()


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
    msg = recv_encrypted(conn, server_private_key)
    if msg is None:
        print("Клиент отключился.")
        break
    print(f"Клиент: {msg}")
    
    reply = input("Сервер: ")
    if reply.lower() == 'exit':
        break
    send_encrypted(conn, reply, client_public_key)

conn.close()
server_socket.close()