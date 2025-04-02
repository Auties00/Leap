package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.nio.ByteBuffer;

public record ServerHelloDoneMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    public static final byte ID = 0x0E;

    public static ServerHelloDoneMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        if(buffer.hasRemaining()) {
            throw new TlsAlert("Expected server hello done message to have an empty payload", URI.create("https://datatracker.ietf.org/doc/html/rfc5246"), "7.4.5");
        }

        return new ServerHelloDoneMessage(metadata.version(), metadata.source());
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
        switch (context.mode()) {
            case CLIENT -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .setHelloDone(true);
            case SERVER -> context.localConnectionState()
                    .setHelloDone(true);
        }
    }
}
