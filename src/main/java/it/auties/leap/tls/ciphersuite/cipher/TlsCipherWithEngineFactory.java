package it.auties.leap.tls.ciphersuite.cipher;

import it.auties.leap.tls.ciphersuite.exchange.TlsExchangeMac;

public interface TlsCipherWithEngineFactory {
    TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator);
    int ivLength();
    int fixedIvLength();
    int tagLength();
    default boolean aead() {
        return tagLength() != 0;
    }
}
