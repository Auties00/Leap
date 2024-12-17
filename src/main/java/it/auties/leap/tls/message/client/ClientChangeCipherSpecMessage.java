package it.auties.leap.tls.message.client;

import it.auties.leap.tls.BufferHelper;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.util.List;

public final class ClientChangeCipherSpecMessage extends TlsHandshakeMessage {
    private static final int ID = 0x01;
    private static final int LENGTH = 0;

    public ClientChangeCipherSpecMessage(TlsVersion tlsVersion, Source source) {
        super(tlsVersion, source);
    }

    public static ClientChangeCipherSpecMessage of(TlsVersion tlsVersion, Source source, int messageLength) {
        if(messageLength != LENGTH) {
            throw new IllegalArgumentException("Cannot decode TLS message, invalid payload length");
        }

        return new ClientChangeCipherSpecMessage(tlsVersion, source);
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || (precedingMessages.getLast() != Type.CLIENT_KEY_EXCHANGE && precedingMessages.getLast() != Type.CLIENT_CERTIFICATE_VERIFY)) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsMode.CLIENT;
                case REMOTE -> mode == TlsMode.SERVER;
            };
            case UDP -> false;
        };
    }

    @Override
    public Type type() {
        return Type.CLIENT_CHANGE_CIPHER_SPEC;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public ContentType contentType() {
        return ContentType.CHANGE_CIPHER_SPEC;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        BufferHelper.writeLittleEndianInt8(buffer, id());
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
