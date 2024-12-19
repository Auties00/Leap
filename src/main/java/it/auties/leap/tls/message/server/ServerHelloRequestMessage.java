package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.net.URI;
import java.nio.ByteBuffer;

public final class ServerHelloRequestMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x00;

    public ServerHelloRequestMessage(TlsVersion tlsVersion, TlsSource source) {
        super(tlsVersion, source);
    }

    public static ServerHelloRequestMessage of(TlsVersion version, TlsSource source, int messageLength) {
        if(messageLength != 0) {
            throw new TlsException("Expected server hello request message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"), "7.4.1.1");
        }

        return new ServerHelloRequestMessage(version, source);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_HELLO_REQUEST;
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
