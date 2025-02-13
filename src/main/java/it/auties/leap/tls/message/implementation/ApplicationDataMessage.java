package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.util.BufferUtils;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class ApplicationDataMessage extends TlsMessage {
    private static final int ID = 0x17;

    private final ByteBuffer message;
    public ApplicationDataMessage(TlsVersion tlsVersion, TlsSource source, ByteBuffer message) {
        super(tlsVersion, source);
        this.message = message;
    }

    public static ApplicationDataMessage of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
        var message = readBuffer(buffer, buffer.remaining());
        return new ApplicationDataMessage(metadata.version(), metadata.source(), message);
    }

    public static void serializeInline(TlsVersion version, ByteBuffer message) {
        var messageLength = message.remaining();
        if(message.position() < messageRecordHeaderLength()) {
           throw new BufferUnderflowException();
        }

        var newReadPosition = message.position() - messageRecordHeaderLength();
        message.position(newReadPosition);
        writeBigEndianInt8(message, ContentType.APPLICATION_DATA.id());
        writeBigEndianInt8(message, version.id().major());
        writeBigEndianInt8(message, version.id().minor());
        writeBigEndianInt16(message, messageLength);
        message.position(newReadPosition);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.APPLICATION_DATA;
    }

    @Override
    public ContentType contentType() {
        return ContentType.APPLICATION_DATA;
    }

    @Override
    public void serializeMessagePayload(ByteBuffer buffer) {
        BufferUtils.assertNotEquals(buffer, message);
        writeBuffer(buffer, message);
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

    public ByteBuffer message() {
        return message;
    }
}
