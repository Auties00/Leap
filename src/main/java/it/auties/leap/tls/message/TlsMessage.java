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
    public abstract void serializePayload(ByteBuffer buffer);
    public abstract int payloadLength();
    public abstract void apply(TlsContext context);

    public void serializeWithRecord(ByteBuffer payload) {
        var messagePayloadLength = payloadLength();
        var recordLength = recordHeaderLength() + messagePayloadLength;
        try(var _ = scopedWrite(payload, recordLength, true)) {
            writeBigEndianInt8(payload, contentType().type());
            writeBigEndianInt8(payload, version().id().major());
            writeBigEndianInt8(payload, version().id().minor());
            writeBigEndianInt16(payload, messagePayloadLength);
            serializePayload(payload);
        }
    }

    public void serialize(ByteBuffer payload) {
        try(var _ = scopedWrite(payload, payloadLength(), true)) {
            serializePayload(payload);
        }
    }

    public static int recordHeaderLength() {
        return INT8_LENGTH + INT8_LENGTH + INT8_LENGTH + INT16_LENGTH;
    }

    public static void putRecord(TlsVersion version, TlsMessageContentType type, ByteBuffer message) {
        var messageLength = message.remaining();
        if(message.position() < recordHeaderLength()) {
            throw new BufferUnderflowException();
        }

        var newReadPosition = message.position() - recordHeaderLength();
        message.position(newReadPosition);
        writeBigEndianInt8(message, type.type());
        writeBigEndianInt8(message, version.id().major());
        writeBigEndianInt8(message, version.id().minor());
        writeBigEndianInt16(message, messageLength);
        message.position(newReadPosition);
    }
}
