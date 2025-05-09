package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
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
    private static final int ID = 0x14;
    private static final int MIN_HASH_LENGTH = 12;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var hash = readBytes(buffer, buffer.remaining());
            return new FinishedMessage(metadata.version(), metadata.source(), hash);
        }
    };

    public static TlsHandshakeMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    public FinishedMessage {
        if(hash == null || hash.length < MIN_HASH_LENGTH) {
            throw new TlsAlert("The hash should be at least %s bytes long".formatted(MIN_HASH_LENGTH), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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
        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setHandshakeStatus(TlsConnectionHandshakeStatus.HANDSHAKE_FINISHED);

            case REMOTE -> {
                context.remoteConnectionState()
                                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .setHandshakeStatus(TlsConnectionHandshakeStatus.HANDSHAKE_FINISHED);
                var expectedHash = context.connectionHandshakeHash()
                        .finish(context, TlsSource.REMOTE);
                if(!Arrays.equals(expectedHash, hash)) {
                    // throw new TlsAlert("Cannot validate hash", TlsAlertLevel.FATAL, TlsAlertType.HANDSHAKE_FAILURE);
                    System.out.println("Remote hash doesn't match expected value");
                }
            }
        }

        context.connectionHandler()
                .finalize(context, source);
    }

    @Override
    public boolean hashable() {
        return true;
    }

    public void validate(TlsContext context) {

    }
}
