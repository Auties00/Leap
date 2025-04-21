package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class HandshakeMessageDeserializer implements TlsMessageDeserializer {
    private static final HandshakeMessageDeserializer INSTANCE = new HandshakeMessageDeserializer();

    private HandshakeMessageDeserializer() {

    }

    public static TlsMessageDeserializer instance() {
        return INSTANCE;
    }

    @Override
    public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        var id = readBigEndianInt8(buffer);
        var handshakePayloadLength = readBigEndianInt24(buffer);
        try (var _ = scopedRead(buffer, handshakePayloadLength)) {
            return context.findHandshakeMessageDeserializer(id)
                    .map(deserializer -> deserializer.deserialize(context, buffer, metadata.withLength(handshakePayloadLength)))
                    .orElseThrow(() -> new TlsAlert("Unknown message type: " + id, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        }
    }
}
