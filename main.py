from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=2, key_size=512)

class Party:
    # konstruktor
    def __init__(self,identity):
        self.identity=identity
        self.identity_mac=None

        self.private_key=parameters.generate_private_key()
        self.public_key=self.private_key.public_key()

        self.shared_key=None

        self.opponent_public_key=None
        self.opponent_identity=None
        self.opponent_identity_mac=None

    # Jeżeli mamy klucz publiczny przeciwnika, generujemy z niego i z naszego prywatnego klucz współdzielony
    def generateSharedKey(self):
        self.shared_key=self.private_key.exchange(self.opponent_public_key)

    # Generuje swój MAC ze swojej tożsamości
    def generateIdentityMAC(self):
        h=hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(bytearray(self.identity.encode()))
        self.identity_mac=h.finalize()

    # Wylicza MAC z danych przeciwnika, i porównuje z odebranym MAC-iem
    def verifyOpposingMAC(self):
        h=hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(bytes(self.opponent_identity.encode()))
        result=h.finalize()
        print("Zgodność MAC wygenerowanego lokalnie z odebranym:",self.opponent_identity_mac==result)

# Instancjowanie obiektów klasy Party jako partie A i B o podanych tożsamościach
A=Party("Alice")
B=Party("Bob")

# KROK 1 = A wysyła do B
B.opponent_public_key = A.public_key    # Swój klucz publiczny

# KROK 2 = B wysyła do A
A.opponent_public_key = B.public_key    # Swój klucz publiczny
A.opponent_identity   = B.identity      # Swoją tożsamość (surową)

A.generateSharedKey()                   # Ponieważ obie strony mają klucze publiczne przeciwnika i swoje prywatne
B.generateSharedKey()                   # wygenerują na podstawie nich klucz współdzielony

B.generateIdentityMAC()                 # B wygeneruje MAC swojej tożsamości z klucza współdzielonego
A.generateIdentityMAC()                 # A wygeneruje MAC swojej tożsamości z klucza współdzielonego (nie jest potrzebne jeszcze w tym kroku)

A.opponent_identity_mac=B.identity_mac  # B wyśle do A swój MAC z tożsamości
print("A sprawdzi teraz MAC z B")
A.verifyOpposingMAC()                   # A sam wyliczy MAC i zweryfikuje z odebranym

# KROK 3 = A wysyła do B
B.opponent_identity     = A.identity       # Swoją tożsamość (surową)
B.opponent_identity_mac = A.identity_mac   # Swój MAC ze swojej tożsamości
print("B sprawdzi teraz MAC z A")
B.verifyOpposingMAC()

print("Zgodność współdzielonych kluczy:",A.shared_key==B.shared_key)

# serializacja kluczy - to robiłem jak się siłowałem z podpisami cyfrowymi
A_private_key_serialized=A.private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
