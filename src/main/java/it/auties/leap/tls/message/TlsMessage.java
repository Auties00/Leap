package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.AlertMessage;
import it.auties.leap.tls.message.implementation.ApplicationDataMessage;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class TlsMessage
        permits AlertMessage, ApplicationDataMessage, TlsHandshakeMessage {
    protected final TlsVersion version;
    protected final TlsSource source;
    protected TlsMessage(TlsVersion version, TlsSource source) {
        this.version = version;
        this.source = source;
    }

    public TlsVersion version() {
        return version;
    }
    public TlsSource source() {
        return source;
    }

    public abstract byte id();

    public abstract TlsMessageContentType contentType();
    public abstract void serializeMessagePayload(ByteBuffer buffer);
    public abstract int messagePayloadLength();
    public abstract void apply(TlsContext context);

    public void serializeMessageWithRecord(ByteBuffer payload) {
        var messagePayloadLength = messagePayloadLength();
        var recordLength = messageRecordHeaderLength() + messagePayloadLength;
        try(var _ = scopedWrite(payload, recordLength, true)) {
            writeBigEndianInt8(payload, contentType().type());
            writeBigEndianInt8(payload, version().id().major());
            writeBigEndianInt8(payload, version().id().minor());
            writeBigEndianInt16(payload, messagePayloadLength);
            serializeMessagePayload(payload);
        }
    }

    public void serializeMessage(ByteBuffer payload) {
        try(var _ = scopedWrite(payload, messagePayloadLength(), true)) {
            serializeMessagePayload(payload);
        }
    }

    public static int messageRecordHeaderLength() {
        return INT8_LENGTH + INT8_LENGTH + INT8_LENGTH + INT16_LENGTH;
    }

    public static void putRecord(TlsVersion version, TlsMessageContentType type, ByteBuffer message) {
        var messageLength = message.remaining();
        if(message.position() < messageRecordHeaderLength()) {
            throw new BufferUnderflowException();
        }

        var newReadPosition = message.position() - messageRecordHeaderLength();
        message.position(newReadPosition);
        writeBigEndianInt8(message, type.type());
        writeBigEndianInt8(message, version.id().major());
        writeBigEndianInt8(message, version.id().minor());
        writeBigEndianInt16(message, messageLength);
        message.position(newReadPosition);
    }
}
