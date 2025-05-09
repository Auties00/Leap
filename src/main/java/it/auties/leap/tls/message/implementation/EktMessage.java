package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.srtp.SrtpEktKey;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public record EktMessage(
        TlsVersion version,
        TlsSource source,
        SrtpEktKey key
) implements TlsHandshakeMessage {
    private static final byte ID = 0x1A;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var key = SrtpEktKey.of(buffer);
            return new EktMessage(metadata.version(), metadata.source(), key);
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
        key.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return key.length();
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
