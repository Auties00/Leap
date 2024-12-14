package it.auties.leap.tls.message.shared;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsBuffer;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsMessage;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.TlsBuffer.*;

public final class ApplicationDataMessage extends TlsMessage {
    private static final int ID = 0x17;

    private final ByteBuffer message;
    public ApplicationDataMessage(TlsVersion tlsVersion, Source source, ByteBuffer message) {
        super(tlsVersion, source);
        this.message = message;
    }

    public static ApplicationDataMessage of(TlsVersion version, Source source, ByteBuffer buffer) {
        var message = readBuffer(buffer, buffer.remaining());
        return new ApplicationDataMessage(version, source, message);
    }

    public static void serializeInline(TlsVersion version, ByteBuffer message) {
        var messageLength = message.remaining();
        if(message.position() < messageRecordHeaderLength()) {
           throw new BufferUnderflowException();
        }

        var newReadPosition = message.position() - messageRecordHeaderLength();
        message.position(newReadPosition);
        writeLittleEndianInt8(message, ContentType.APPLICATION_DATA.id());
        writeLittleEndianInt8(message, version.id().major());
        writeLittleEndianInt8(message, version.id().minor());
        writeLittleEndianInt16(message, messageLength);
        message.position(newReadPosition);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        return switch (version.protocol()) {
            case TCP -> switch (mode) {
                case CLIENT -> {
                    var marker = switch (source) {
                        case REMOTE -> Type.SERVER_CHANGE_CIPHER_SPEC;
                        case LOCAL -> Type.CLIENT_CHANGE_CIPHER_SPEC;
                    };
                    yield precedingMessages.contains(marker);
                }
                case SERVER -> {
                    var marker = switch (source) {
                        case REMOTE -> Type.CLIENT_CHANGE_CIPHER_SPEC;
                        case LOCAL -> Type.SERVER_CHANGE_CIPHER_SPEC;
                    };
                    yield precedingMessages.contains(marker);
                }
            };
            case UDP -> false;
        };
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
        TlsBuffer.assertNotEquals(buffer, message);
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
