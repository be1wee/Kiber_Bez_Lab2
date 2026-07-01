import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Сервер запущен. Ожидаем подключения...")

conn, addr = server_socket.accept()
print(f"Клиент подключился: {addr}")


conn.sendall(server_public_pem)


client_public_pem = conn.recv(4096)
client_public_key = serialization.load_pem_public_key(
    client_public_pem,
    backend=default_backend()
)


def send_encrypted(data, public_key):
    encrypted = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    conn.sendall(len(encrypted).to_bytes(4, 'big'))  
    conn.sendall(encrypted)                          

def recv_encrypted(private_key):
    raw_len = conn.recv(4)
    if not raw_len:          
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    encrypted_data = conn.recv(msg_len)
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
    
    msg_from_client = recv_encrypted(server_private_key)
    if msg_from_client is None:
        break
    print("Клиент:", msg_from_client)

    
    reply = input("Сервер ('exit' для завершения): ")
    if reply.lower() == 'exit':
        break
    
    send_encrypted(reply, client_public_key)

conn.close()
server_socket.close()