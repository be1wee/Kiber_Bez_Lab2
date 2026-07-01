import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key = client_private_key.public_key()
client_public_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))
print("Подключено к серверу.")


server_public_pem = client_socket.recv(4096)
server_public_key = serialization.load_pem_public_key(
    server_public_pem,
    backend=default_backend()
)


client_socket.sendall(client_public_pem)


def send_encrypted(data, public_key):
    encrypted = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.sendall(len(encrypted).to_bytes(4, 'big'))
    client_socket.sendall(encrypted)

def recv_encrypted(private_key):
    raw_len = client_socket.recv(4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    encrypted_data = client_socket.recv(msg_len)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')


while True:
    
    message = input("Клиент ('exit' для выхода): ")
    if message.lower() == 'exit':
        break
    
    send_encrypted(message, server_public_key)

    
    reply = recv_encrypted(client_private_key)
    if reply is None:
        break
    print("Сервер:", reply)

client_socket.close()
print("Клиент завершил работу.")