package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.net.URI;
import java.nio.ByteBuffer;

public final class ServerHelloDoneMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0E;

    public ServerHelloDoneMessage(TlsVersion tlsVersion, TlsSource source) {
        super(tlsVersion, source);
    }

    public static ServerHelloDoneMessage of(TlsVersion version, TlsSource source, int messageLength) {
        if(messageLength != 0) {
            throw new TlsException("Expected server hello done message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246"), "7.4.5");
        }

        return new ServerHelloDoneMessage(version, source);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_HELLO_DONE;
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {

    }

    @Override
    public int handshakePayloadLength() {
        return 0;
    }
}
