package it.auties.leap.tls.message;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public interface TlsHandshakeMessage extends TlsMessage {
    int payloadLength();
    void serializePayload(ByteBuffer buffer);
    boolean hashable();

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
        var handshakePayloadLength = payloadLength();
        if (handshakePayloadLength > 0) {
            writeBigEndianInt24(buffer, handshakePayloadLength);
            serializePayload(buffer);
        }
    }

    @Override
    default int length() {
        var handshakePayloadLength = payloadLength();
        if (handshakePayloadLength > 0) {
            return INT8_LENGTH + INT24_LENGTH + handshakePayloadLength;
        }else {
            return INT8_LENGTH;
        }
    }
}
