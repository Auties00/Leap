package it.auties.leap.tls.cipher.mode;

import it.auties.leap.tls.cipher.exchange.TlsExchangeMac;

public interface TlsCipherWithEngineFactory {
    TlsCipher newCipher(boolean forEncryption, byte[] key, byte[] fixedIv, TlsExchangeMac authenticator);
    int ivLength();
    int fixedIvLength();
    int tagLength();
    default boolean aead() {
        return tagLength() != 0;
    }
}
