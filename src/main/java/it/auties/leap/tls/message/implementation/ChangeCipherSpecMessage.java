package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ChangeCipherSpecMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    public static final int ID = 0x01;

    public static ChangeCipherSpecMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        if(buffer.hasRemaining()) {
            throw new TlsAlert("Expected change cipher spec message to have an empty payload");
        }

        return new ChangeCipherSpecMessage(metadata.version(), metadata.source());
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.CHANGE_CIPHER_SPEC;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    public int handshakePayloadLength() {
        return INT8_LENGTH;
    }

    @Override
    public void apply(TlsContext context) {

    }
}
