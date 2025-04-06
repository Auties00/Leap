package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
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
    private static final TlsMessageDeserializer DESERIALIZER = new TlsMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var ticketLifetimeHint = readBigEndianInt32(buffer);
            var ticket = readBytesBigEndian16(buffer);
            return new NewSessionTicketMessage(metadata.version(), metadata.source(), ticketLifetimeHint, ticket);
        }
    };

    public static TlsMessageDeserializer deserializer() {
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
}
