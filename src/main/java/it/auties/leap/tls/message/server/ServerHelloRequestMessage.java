package it.auties.leap.tls.message.server;

import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;

public final class ServerHelloRequestMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x00;

    public ServerHelloRequestMessage(TlsVersion tlsVersion, Source source) {
        super(tlsVersion, source);
    }

    public static ServerHelloRequestMessage of(TlsVersion version, Source source, int messageLength) {
        if(messageLength != 0) {
            throw new TlsSpecificationException("Expected server hello request message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"), "7.4.1.1");
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
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        return version != TlsVersion.TLS13 && version != TlsVersion.DTLS13;
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
