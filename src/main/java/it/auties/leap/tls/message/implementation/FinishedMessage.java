package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static it.auties.leap.tls.util.BufferUtils.readBytes;
import static it.auties.leap.tls.util.BufferUtils.writeBytes;

public record FinishedMessage(
        TlsVersion version,
        TlsSource source,
        byte[] hash
) implements TlsHandshakeMessage {
    public static final int ID = 0x14;
    private static final int MIN_HASH_LENGTH = 12;

    public static FinishedMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        var hash = readBytes(buffer, buffer.remaining());
        return new FinishedMessage(metadata.version(), metadata.source(), hash);
    }

    public FinishedMessage {
        if(hash == null || hash.length < MIN_HASH_LENGTH) {
            throw new TlsAlert("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH));
        }
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
    public void serializePayload(ByteBuffer buffer) {
        writeBytes(buffer, hash);
    }

    @Override
    public int payloadLength() {
        return hash.length;
    }

    @Override
    public void apply(TlsContext context) {
        System.out.println("Hash from " + source + " " + Arrays.toString(hash));
        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_FINISHED);
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_FINISHED);
        }
    }
}
