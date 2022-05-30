from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=2, key_size=512)

server_private_key = parameters.generate_private_key()
peer_private_key = parameters.generate_private_key()

server_public_key = server_private_key.public_key()
peer_public_key = peer_private_key.public_key()

shared_key_a = server_private_key.exchange(peer_public_key=peer_public_key)
shared_key_b = peer_private_key.exchange(server_public_key)

print("SERVER PRIVATE KEY",server_private_key)
print("SERVER PUBLIC KEY",server_public_key)
print("PEER PRIVATE KEY",peer_private_key)
print("PEER PUBLIC KEY",peer_public_key)
print("SHARED KEY A",shared_key_a)
print("SHARED KEY B",shared_key_b)
print("ARE SHARED KEYS EQUAL:",shared_key_a==shared_key_b)