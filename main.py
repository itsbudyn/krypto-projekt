from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Party:
    def __init__(self,identity):
        self.identity=identity
        self.private_key=parameters.generate_private_key()
        self.public_key=self.private_key.public_key()

        self.shared_key=None

        self.opponent_public_key=None

    def generateSharedKey(self):
        self.shared_key=self.private_key.exchange(self.opponent_public_key)