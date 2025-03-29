package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ApplicationDataMessage(
        TlsVersion version,
        TlsSource source,
        ByteBuffer message
) implements TlsMessage {
    public static final int ID = 0x17;

    public static ApplicationDataMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        var message = readBuffer(buffer, buffer.remaining());
        return new ApplicationDataMessage(metadata.version(), metadata.source(), message);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.APPLICATION_DATA;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        assertNotEquals(buffer, message);
        writeBuffer(buffer, message);
    }

    @Override
    public void apply(TlsContext context) {
        if (source == TlsSource.REMOTE) {
            context.addBufferedMessage(message);
        }
    }

    @Override
    public int payloadLength() {
        return message.remaining();
    }
}
