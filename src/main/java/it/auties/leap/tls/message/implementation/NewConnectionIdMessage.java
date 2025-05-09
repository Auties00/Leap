package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.connection.TlsConnectIdUsage;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record NewConnectionIdMessage(
        TlsVersion version,
        TlsSource source,
        List<byte[]> ids,
        int idsLength,
        TlsConnectIdUsage usage
) implements TlsHandshakeMessage {
    private static final byte ID = 0x0A;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var ids = new ArrayList<byte[]>();
            var idsLength = readBigEndianInt16(buffer);
            try(var _ = scopedRead(buffer, idsLength)) {
                while (buffer.hasRemaining()) {
                    var connectionId = readBytesBigEndian8(buffer);
                    ids.add(connectionId);
                }
            }
            var usageId = readBigEndianInt8(buffer);
            var usage = TlsConnectIdUsage.of(usageId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown connection id usage: " + usageId));
            return new NewConnectionIdMessage(metadata.version(), metadata.source(), ids, idsLength, usage);
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
        writeBigEndianInt16(buffer, idsLength);
        for(var id : ids) {
            writeBytesBigEndian8(buffer, id);
        }
        writeBigEndianInt8(buffer, usage.id());
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH
                + idsLength
                + INT8_LENGTH;
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
