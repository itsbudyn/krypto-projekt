# krypto-projekt
Implementacja podstawowego protokołu wymiany kluczy SIGMA na seminarium z kryptografii.

- Implementacja została zrobiona na modułach `cryptography.hazmat.primitives` - `hashes`, `hmac`, `dsa`, `dh`, `serialization`
- Przed użyciem należy zainstalować bibliotekę `crpytography` - `python -m pip install cryptography`
- Protokół nie jest 100% odzwierciedleniem protokołu SIGMA - Powodem jest brak możliwości użycia kluczy Diffie-Hellmana w bibliotekach do podpisów cyfrowych - dla podpisów zostały wygenerowane klucze DSA.
- Nie została zastosowana funkcja KDF dla klucza wspólnego w celu uproszczenia demonstracji - należy takową zastosować przy rzeczywistej implementacji.
