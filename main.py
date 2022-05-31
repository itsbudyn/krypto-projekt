from Party import *

# Instancjowanie obiektów klasy Party jako partie A i B o podanych tożsamościach
A=Party()
B=Party()

# KROK 1 = A wysyła do B
B.opponent_dh_exponential   = A.dh_exponential  # Swój klucz DH publiczny

# KROK 2 = B wysyła do A
A.opponent_dh_exponential   = B.dh_exponential  # B wysyła do A swój klucz DH publiczny

A.opponent_identity         = B.identity        # B wysyła do A swoją tożsamość (surową)

B.generateSignChallenge()   # B wygeneruje dla A wyzwanie - podpis kluczy publicznych DH
A.opponent_sign_challenge   = B.sign_challenge  # B wyśle do A wyzwanie podpisowe

# WYLICZENIE KLUCZY WSPÓŁDZIELONYCH
A.generateSharedKey()       # Ponieważ obie strony mają klucze publiczne DH przeciwnika i swoje prywatne
B.generateSharedKey()       # wygenerują na podstawie nich klucz wspólny

B.generateIdentityMAC()     # B wyliczy MAC swojej tożsamości z klucza współdzielonego
A.generateIdentityMAC()     # A wyliczy MAC swojej tożsamości z klucza współdzielonego (nie jest potrzebne jeszcze w tym kroku)
A.opponent_identity_mac     = B.identity_mac    # B wyśle do A wyliczony MAC z tożsamości

# KROK 3 = A wysyła do B
B.opponent_identity         = A.identity        # A wysyła do B swoją tożsamość (surową)

A.generateSignChallenge()   # A wygeneruje dla B wyzwanie - podpis kluczy publicznych DH
B.opponent_sign_challenge   = A.sign_challenge  # A wyśle do B wyzwanie podpisowe

B.opponent_identity_mac     = A.identity_mac    # A wysyła do B wyliczony MAC ze swojej tożsamości

# WERYFIKACJE ZGODNOŚCI
print("Zgodność podpisu od B:\t\t\t\t",A.verifySignChallenge(A.opponent_identity))          # A zweryfikuje podpis od B
print("Zgodność MAC wygenerowanego w A z tym od B:\t", A.verifyOpposingMAC())   # A sam wyliczy MAC i zweryfikuje z odebranym
print("Zgodność podpisu od A:\t\t\t\t",B.verifySignChallenge(B.opponent_identity))          # B zweryfikuje podpis od A
print("Zgodność MAC wygenerowanego w B z tym od A:\t", B.verifyOpposingMAC())   # B sam wyliczy MAC i zweryfikuje z odebranym
print("Zgodność współdzielonych kluczy:\t\t",A.shared_key==B.shared_key)                # Zostnie sprawdzona ostatecznie równość wyliczonych kluczy współdzielonych
print("Jeżeli wszystkie 5 weryfikacje przebiegły pomyślnie - klucz współdzielony jest prawidłowy")
# Jeżeli wszystkie linijki będą true, transmisja w protokole SIGMA się powiodła