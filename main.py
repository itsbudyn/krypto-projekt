from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa

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

# Instancjowanie obiektów klasy Party jako partie A i B o podanych tożsamościach
A=Party()
B=Party()

# KROK 1 = A wysyła do B
B.opponent_dh_exponential   = A.dh_exponential  # Swój klucz DH publiczny

# KROK 2 = B wysyła do A
A.opponent_dh_exponential   = B.dh_exponential  # Swój klucz DH publiczny
A.opponent_identity         = B.identity        # Swoją tożsamość (surową)

A.generateSharedKey()       # Ponieważ obie strony mają klucze publiczne DH przeciwnika i swoje prywatne
B.generateSharedKey()       # wygenerują na podstawie nich klucz wspólny

B.generateIdentityMAC()     # B wyliczy MAC swojej tożsamości z klucza współdzielonego
A.generateIdentityMAC()     # A wyliczy MAC swojej tożsamości z klucza współdzielonego (nie jest potrzebne jeszcze w tym kroku)

B.generateSignChallenge()   # B wygeneruje dla A wyzwanie - podpis kluczy publicznych DH

A.opponent_identity_mac=B.identity_mac      # B wyśle do A wyliczony MAC z tożsamości
A.opponent_sign_challenge=B.sign_challenge  # B wyśle do A wyzwanie podpisowe

print("Zgodność podpisu od B:",A.verifySignChallenge(A.opponent_identity))          # A zweryfikuje podpis od B
print("Zgodność MAC wygenerowanego w A z odebranym od B:", A.verifyOpposingMAC())   # A sam wyliczy MAC i zweryfikuje z odebranym

# KROK 3 = A wysyła do B
B.opponent_identity     = A.identity       # Swoją tożsamość (surową)
B.opponent_identity_mac = A.identity_mac   # Wyliczony MAC ze swojej tożsamości

A.generateSignChallenge()   # A wygeneruje dla B wyzwanie - podpis kluczy publicznych DH

B.opponent_sign_challenge = A.sign_challenge    # A wyśle do B wyzwanie podpisowe

print("Zgodność podpisu od A:",B.verifySignChallenge(B.opponent_identity))          # B zweryfikuje podpis od A
print("Zgodność MAC wygenerowanego w B z odebranym od A:", B.verifyOpposingMAC())   # B sam wyliczy MAC i zweryfikuje z odebranym

print("Zgodność współdzielonych kluczy:",A.shared_key==B.shared_key)    # Zostnie sprawdzona ostatecznie równość wyliczonych kluczy współdzielonych

# Jeżeli wszystkie linijki będą true, transmisja w protokole SIGMA się powiodła