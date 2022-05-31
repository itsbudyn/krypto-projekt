from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa

# parametry dla generatora kluczy Diffie-Hellmana
parameters = dh.generate_parameters(generator=2, key_size=512)

class Party:
    # konstruktor
    def __init__(self):
        self.private_key    = dsa.generate_private_key(key_size=1024)   # Generacja klucza prywatnego DSA
        self.identity       = self.private_key.public_key()             # Klucz publiczny DSA będzie tożsamością partii
        
        self.identity_mac   = None      # MAC z tożsamości

        self.dh_secret      = parameters.generate_private_key() # x albo y     - generalnie "klucz prywatny" algorytmu Diffie-Hellmana
        self.dh_exponential = self.dh_secret.public_key()       # g^x albo g^y - generalnie "klucz publiczny" algorytmu Diffie-Hellmana

        self.shared_key     = None  # Tu będzie klucz współdzielony Diffie-Hellmana - nasz główny cel

        self.sign_challenge = None  # Tu będzie challenge - podpisanie kluczy publicznych swoich i przeciwnika

        # Poniższe wartości pohodzą od przeciwnika
        self.opponent_dh_exponential= None  # Tu jest "klucz publiczny" Diffie-Hellmana
        self.opponent_identity      = None  # Tu jest tożsamość - klucz publiczny DSA
        self.opponent_identity_mac  = None  # Tu jest wyliczony kod MAC
        self.opponent_sign_challenge= None  # Tu jest challenge, czyli podpisane klucze

    # Jeżeli mamy klucz publiczny DH przeciwnika, generujemy z niego i z naszego prywatnego klucza DH klucz współdzielony
    # Wynik = uzupełnia atrybut shared_key
    def generateSharedKey(self):
        self.shared_key = self.dh_secret.exchange(self.opponent_dh_exponential)

    # Wylicza MAC ze swojej tożsamości
    # Wynik = uzupełnia atrybut identity_mac
    def generateIdentityMAC(self):
        h = hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(self.serializeRSAPublicKey(self.identity))
        self.identity_mac=h.finalize()

    # Wylicza MAC z tożsamości przeciwnika, i porównuje z odebranym MAC-iem
    # Wynik = boolean (True/False) zależny od równości MAC'ów
    def verifyOpposingMAC(self):
        h = hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(self.serializeRSAPublicKey(self.opponent_identity))
        result = h.finalize()
        return self.opponent_identity_mac==result

    # Konwertuje klucz publiczny DSA na bytearray
    # Wynik = bytearray
    def serializeRSAPublicKey(self,key:dsa.DSAPublicKey):
        return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Konwertuje klucz publiczny DH na bytearray
    # Wynik = bytearray
    def serializeDHExponent(self,key:dh.DHPublicKey):
        return key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Generuje wyzwanie - sumuje stringi (konkatenacja) z kluczy publicznych DH swojego i przeciwnika, a następnie podpisuje
    # Wynik = uzupełnia atrybut sign_challenge o podpis
    def generateSignChallenge(self):
        msg = self.serializeDHExponent(self.dh_exponential).decode() + self.serializeDHExponent(self.opponent_dh_exponential).decode()
        self.sign_challenge = self.private_key.sign(msg.encode(), hashes.SHA256())

    # Weryfikuje podpis z wyzwania przeciwnika
    # Wynik = True (w przypadku niepowodzenia jest zgłaszany wyjątek)
    def verifySignChallenge(self, key:dsa.DSAPublicKey):
        msg = self.serializeDHExponent(self.opponent_dh_exponential).decode() + self.serializeDHExponent(self.dh_exponential).decode()
        key.verify(self.opponent_sign_challenge, msg.encode(), hashes.SHA256())
        return True