package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionKeyUpdateRequestType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record KeyUpdateRequestMessage(
        TlsVersion version,
        TlsSource source,
        TlsConnectionKeyUpdateRequestType requestType
) implements TlsHandshakeMessage {
    private static final byte ID = 0x18;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            if(buffer.hasRemaining()) {
                throw new TlsAlert("Expected supplemental data message to have an empty payload", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            var requestTypeId = readBigEndianInt8(buffer);
            var requestType = TlsConnectionKeyUpdateRequestType.of(requestTypeId)
                    .orElseThrow(() -> new TlsAlert("Unknown request type id: " + requestTypeId, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
            return new KeyUpdateRequestMessage(metadata.version(), metadata.source(), requestType);
        }
    };

    public static TlsHandshakeMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.HANDSHAKE;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, requestType.id());
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH;
    }

    @Override
    public void apply(TlsContext context) {

    }
}
