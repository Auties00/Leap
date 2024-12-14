package it.auties.leap.tls.crypto.cipher.wrap;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.crypto.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.crypto.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

final class MGMWrapper extends TlsCipherWrapper {
    private final boolean reducedKeySize;

    MGMWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode, boolean reducedKeySize) {
        super(version, cipher, authenticator, sessionKeys, mode);
        this.reducedKeySize = reducedKeySize;
    }

    @Override
    public void encrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void decrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int nonceLength() {
        return 0;
    }
}
