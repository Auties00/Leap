package it.auties.leap.tls.cipher.wrapper;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import java.nio.ByteBuffer;

final class CCMWrapper extends TlsCipherWrapper {
    private static final int BLOCK_SIZE = 16;

    private final boolean reducedKeySize;

    CCMWrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsMode mode, boolean reducedKeySize) {
        super(version, cipher, authenticator, sessionKeys, mode);
        this.reducedKeySize = reducedKeySize;
    }

    @Override
    public void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int nonceLength() {
        return BLOCK_SIZE;
    }
}
