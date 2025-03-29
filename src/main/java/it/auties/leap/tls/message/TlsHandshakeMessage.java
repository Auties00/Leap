package it.auties.leap.tls.message;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public interface TlsHandshakeMessage extends TlsMessage {
    int handshakePayloadLength();
    void serializeHandshakePayload(ByteBuffer buffer);

    @Override
    default void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
        var handshakePayloadLength = handshakePayloadLength();
        if (handshakePayloadLength > 0) {
            writeBigEndianInt24(buffer, handshakePayloadLength);
            serializeHandshakePayload(buffer);
        }
    }

    @Override
    default int payloadLength() {
        var handshakePayloadLength = handshakePayloadLength();
        return INT8_LENGTH + (handshakePayloadLength > 0 ? INT24_LENGTH + handshakePayloadLength : 0);
    }
}
