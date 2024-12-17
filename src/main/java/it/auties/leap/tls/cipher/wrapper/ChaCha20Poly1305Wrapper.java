package it.auties.leap.tls.cipher.wrapper;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

final class ChaCha20Poly1305Wrapper extends TlsCipherWrapper {
    ChaCha20Poly1305Wrapper(TlsVersion version, TlsCipher cipher, TlsExchangeAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsMode mode) {
        super(version, cipher, authenticator, sessionKeys, mode);
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
