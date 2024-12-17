package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.BufferHelper.*;

public final class ServerChangeCipherSpecMessage extends TlsHandshakeMessage {
    private static final int ID = 0x01;
    private static final int LENGTH = INT8_LENGTH;

    public ServerChangeCipherSpecMessage(TlsVersion tlsVersion, Source source) {
        super(tlsVersion, source);
    }

    public static ServerChangeCipherSpecMessage of(TlsVersion tlsVersion, Source source, ByteBuffer buffer) {
        var messageId = readLittleEndianInt8(buffer);
        if(messageId != ID) {
            throw new IllegalArgumentException("Cannot decode TLS message, invalid change cipher spec message id: " + messageId);
        }

        return new ServerChangeCipherSpecMessage(tlsVersion, source);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_CHANGE_CIPHER_SPEC;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty()) {
            return false;
        }

        var validatedSource = switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.SERVER;
                case REMOTE -> mode == TlsMode.CLIENT;
            };
            case UDP -> false;
        };
        if(!validatedSource) {
            return false;
        }

        var expectedMessage = version == TlsVersion.TLS13 || version == TlsVersion.DTLS13 ? Type.SERVER_HELLO : Type.CLIENT_FINISHED;
        return precedingMessages.getLast() == expectedMessage;
    }

    @Override
    public ContentType contentType() {
        return ContentType.CHANGE_CIPHER_SPEC;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, id());
    }

    @Override
    public int handshakePayloadLength() {
        return LENGTH;
    }

    @Override
    public String toString() {
        return "ChangeCipherSpecMessage[" +
                "tlsVersion=" + version +
                ']';
    }
}
