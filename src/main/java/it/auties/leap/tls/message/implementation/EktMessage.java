package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.srtp.TlsSrtpEktKey;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public record EktMessage(
        TlsVersion version,
        TlsSource source,
        TlsSrtpEktKey key
) implements TlsHandshakeMessage {
    private static final byte ID = 0x1A;
    private static final TlsMessageDeserializer DESERIALIZER = new TlsMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var key = TlsSrtpEktKey.of(buffer);
            return new EktMessage(metadata.version(), metadata.source(), key);
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
        key.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return key.length();
    }

    @Override
    public void apply(TlsContext context) {

    }
}
