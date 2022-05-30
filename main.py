from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=2, key_size=512)

class Party:
    def __init__(self,identity):
        self.identity=identity
        self.private_key=parameters.generate_private_key()
        self.public_key=self.private_key.public_key()

        self.shared_key=None

        self.opponent_public_key=None
        self.opponent_identity=None

    def generateSharedKey(self):
        self.shared_key=self.private_key.exchange(self.opponent_public_key)

    def __str__(self):
        string=f"""INFORMACJE O {self.identity}
        KLUCZ PRYWATNY: \t{self.private_key}
        KLUCZ PUBLICZNY:\t{self.public_key}
        
        KLUCZ WSPÓŁDZIELONY:\t{self.shared_key}
        
        KLUCZ PUB. PRZECIWNY:\t{self.opponent_public_key}"""
        return string

A=Party("A")
B=Party("B")

# KROK 1 = A WYSYŁA g^x DO B
B.opponent_public_key=A.public_key

# KROK 2
A.opponent_public_key=B.public_key
A.opponent_identity=B.identity

print(A.shared_key==B.shared_key)