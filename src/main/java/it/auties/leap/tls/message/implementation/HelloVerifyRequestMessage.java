package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record HelloVerifyRequestMessage(
        TlsVersion version,
        TlsSource source,
        byte[] cookie
) implements TlsHandshakeMessage {
    private static final byte ID = 0x03;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var cookie = readBytesBigEndian8(buffer);
            return new HelloVerifyRequestMessage(metadata.version(), metadata.source(), cookie);
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
        writeBytesBigEndian8(buffer, cookie);
    }

    @Override
    public int payloadLength() {
        return INT8_LENGTH + cookie.length;
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
