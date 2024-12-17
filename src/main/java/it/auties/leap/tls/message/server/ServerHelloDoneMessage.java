package it.auties.leap.tls.message.server;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.List;

public final class ServerHelloDoneMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0E;

    public ServerHelloDoneMessage(TlsVersion tlsVersion, Source source) {
        super(tlsVersion, source);
    }

    public static ServerHelloDoneMessage of(TlsVersion version, Source source, int messageLength) {
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
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
            return false;
        }

        if(precedingMessages.isEmpty() || (precedingMessages.getLast() != Type.SERVER_CERTIFICATE_REQUEST
                && precedingMessages.getLast() != Type.SERVER_KEY_EXCHANGE
                && precedingMessages.getLast() != Type.SERVER_HELLO)) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.SERVER;
                case REMOTE -> mode == TlsMode.CLIENT;
            };
            case UDP -> false;
        };
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
