package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public record CertificateVerifyMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    public static final int ID = 0x0F;

    public static HelloDoneMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        if(buffer.hasRemaining()) {
            throw new TlsAlert("Expected certificate verify message to have an empty payload");
        }

        return new HelloDoneMessage(metadata.version(), metadata.source());
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
    public void serializeHandshakePayload(ByteBuffer buffer) {

    }

    @Override
    public int handshakePayloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context) {

    }
}
