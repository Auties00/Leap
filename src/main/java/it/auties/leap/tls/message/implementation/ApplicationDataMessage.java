package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.util.BufferUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.readBuffer;
import static it.auties.leap.tls.util.BufferUtils.writeBuffer;

public final class ApplicationDataMessage extends TlsMessage {
    private static final int ID = 0x17;

    private final ByteBuffer message;
    public ApplicationDataMessage(TlsVersion tlsVersion, TlsSource source, ByteBuffer message) {
        super(tlsVersion, source);
        this.message = message;
    }

    public static ApplicationDataMessage of(TlsContext ignoredEngine, ByteBuffer buffer, TlsMessageMetadata metadata) {
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
    public void serializeMessagePayload(ByteBuffer buffer) {
        BufferUtils.assertNotEquals(buffer, message);
        writeBuffer(buffer, message);
    }

    @Override
    public void validateAndUpdate(TlsContext context) {
        if(source == TlsSource.REMOTE) {
            context.addMessage(message);
        }
    }

    @Override
    public int messagePayloadLength() {
        return message.remaining();
    }

    @Override
    public String toString() {
        return "ApplicationDataMessage[" +
                "tlsVersion=" + version +
                ']';
    }
}
