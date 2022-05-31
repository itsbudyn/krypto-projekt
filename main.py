from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa

parameters = dh.generate_parameters(generator=2, key_size=512)

class Party:
    # konstruktor
    def __init__(self):
        self.private_key    = dsa.generate_private_key(key_size=1024)
        self.identity       = self.private_key.public_key()
        
        self.identity_mac   = None

        self.dh_secret      = parameters.generate_private_key()
        self.dh_exponential = self.dh_secret.public_key()

        self.shared_key     = None

        self.sign_challenge = None

        self.opponent_dh_exponential= None
        self.opponent_identity      = None
        self.opponent_identity_mac  = None
        self.opponent_sign_challenge= None

    # Jeżeli mamy klucz publiczny przeciwnika, generujemy z niego i z naszego prywatnego klucz współdzielony
    def generateSharedKey(self):
        self.shared_key = self.dh_secret.exchange(self.opponent_dh_exponential)

    # Generuje swój MAC ze swojej tożsamości
    def generateIdentityMAC(self):
        h = hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(self.serializeRSAPublicKey(self.identity))
        self.identity_mac=h.finalize()

    # Wylicza MAC z danych przeciwnika, i porównuje z odebranym MAC-iem
    def verifyOpposingMAC(self):
        h = hmac.HMAC(self.shared_key,hashes.SHA256())
        h.update(self.serializeRSAPublicKey(self.opponent_identity))
        result = h.finalize()
        return self.opponent_identity_mac==result

    def serializeRSAPublicKey(self,key:dsa.DSAPublicKey):
        return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def serializeDHExponent(self,key:dh.DHPublicKey):
        return key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def generateSignChallenge(self):
        msg = self.serializeDHExponent(self.dh_exponential).decode() + self.serializeDHExponent(self.opponent_dh_exponential).decode()
        self.sign_challenge = self.private_key.sign(msg.encode(), hashes.SHA256())

    def verifySignChallenge(self, key:dsa.DSAPublicKey):
        msg = self.serializeDHExponent(self.opponent_dh_exponential).decode() + self.serializeDHExponent(self.dh_exponential).decode()
        key.verify(self.opponent_sign_challenge, msg.encode(), hashes.SHA256())
        return True

# Instancjowanie obiektów klasy Party jako partie A i B o podanych tożsamościach
A=Party()
B=Party()

# KROK 1 = A wysyła do B
B.opponent_dh_exponential   = A.dh_exponential  # Swój klucz DH publiczny

# KROK 2 = B wysyła do A
A.opponent_dh_exponential   = B.dh_exponential  # Swój klucz DH publiczny
A.opponent_identity         = B.identity        # Swoją tożsamość (surową)

A.generateSharedKey()       # Ponieważ obie strony mają klucze publiczne przeciwnika i swoje prywatne
B.generateSharedKey()       # wygenerują na podstawie nich klucz współdzielony

B.generateIdentityMAC()     # B wygeneruje MAC swojej tożsamości z klucza współdzielonego
A.generateIdentityMAC()     # A wygeneruje MAC swojej tożsamości z klucza współdzielonego (nie jest potrzebne jeszcze w tym kroku)

B.generateSignChallenge()

A.opponent_identity_mac=B.identity_mac  # B wyśle do A swój MAC z tożsamości
A.opponent_sign_challenge=B.sign_challenge

print("Zgodność podpisu od B:",A.verifySignChallenge(A.opponent_identity))
print("Zgodność MAC wygenerowanego w A z odebranym od B:", A.verifyOpposingMAC())    # A sam wyliczy MAC i zweryfikuje z odebranym

# KROK 3 = A wysyła do B
B.opponent_identity     = A.identity       # Swoją tożsamość (surową)
B.opponent_identity_mac = A.identity_mac   # Swój MAC ze swojej tożsamości

A.generateSignChallenge()

B.opponent_sign_challenge = A.sign_challenge

print("Zgodność podpisu od A:",B.verifySignChallenge(B.opponent_identity))
print("Zgodność MAC wygenerowanego w B z odebranym od A:", B.verifyOpposingMAC())

print("Zgodność współdzielonych kluczy:",A.shared_key==B.shared_key)