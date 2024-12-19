package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.BufferHelper.*;

public final class ServerChangeCipherSpecMessage extends TlsHandshakeMessage {
    private static final int ID = 0x01;
    private static final int LENGTH = INT8_LENGTH;

    public ServerChangeCipherSpecMessage(TlsVersion tlsVersion, TlsSource source) {
        super(tlsVersion, source);
    }

    public static ServerChangeCipherSpecMessage of(TlsVersion tlsVersion, TlsSource source, ByteBuffer buffer) {
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
