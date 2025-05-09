package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record NewSessionTicketMessage(
        TlsVersion version,
        TlsSource source,
        int ticketLifetimeHint,
        byte[] ticket
) implements TlsHandshakeMessage {
    private static final byte ID = 0x04;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var negotiatedVersion = context.getNegotiatedValue(TlsContextualProperty.version())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            if(negotiatedVersion == TlsVersion.TLS13 || negotiatedVersion == TlsVersion.DTLS13) {
                var ticketLifetime = readBigEndianInt32(buffer);
                var tickedAgeAdd = readBigEndianInt32(buffer);
                var ticketNonce = readBytesBigEndian8(buffer);
                var ticket = readBytesBigEndian16(buffer);
                var extensions = readBytesBigEndian16(buffer);
                return new NewSessionTicketMessage(metadata.version(), metadata.source(), ticketLifetime, ticket);
            }else {
                var ticketLifetimeHint = readBigEndianInt32(buffer);
                var ticket = readBytesBigEndian16(buffer);
                return new NewSessionTicketMessage(metadata.version(), metadata.source(), ticketLifetimeHint, ticket);
            }
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
        writeBigEndianInt32(buffer, ticketLifetimeHint);
        writeBytesBigEndian16(buffer, ticket);
    }

    @Override
    public int payloadLength() {
        return INT32_LENGTH
                + INT16_LENGTH + ticket.length;
    }


    @Override
    public void apply(TlsContext context) {

    }

    @Override
    public boolean hashable() {
        return true;
    }

    public void validate(TlsContext context) {

    }
}
