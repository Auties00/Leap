package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.nio.ByteBuffer;

public record HelloRequestMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    public static final byte ID = 0x00;

    public static HelloRequestMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        if(buffer.hasRemaining()) {
            throw new TlsAlert("Expected server hello request message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"), "7.4.1.1");
        }

        return new HelloRequestMessage(metadata.version(), metadata.source());
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
