package it.auties.leap.tls.encryption.mode;

import it.auties.leap.tls.encryption.TlsEncryption;
import it.auties.leap.tls.auth.TlsAuthenticator;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.ByteBuffer;

public final class Null extends TlsEncryption {
    public Null(TlsAuthenticator authenticator) {
        super(null, null, authenticator, null, null);
    }

    @Override
    public void encrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
        addMac(input, contentType.id());
        move(input, output);
    }

    @Override
    public void decrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence) {
        checkStreamMac(input, contentType.id(), sequence);
        move(input, output);
    }

    @Override
    public int nonceLength() {
        return 0;
    }

    private void move(ByteBuffer input, ByteBuffer output) {
        var outputPosition = output.position();
        output.put(input)
                .limit(output.position())
                .position(outputPosition);
    }
}
