package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

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
    public void serializePayload(ByteBuffer buffer) {

    }

    @Override
    public int payloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context) {
        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .cipher()
                    .orElseThrow(TlsAlert::noLocalCipher)
                    .setEnabled(true);
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .cipher()
                    .orElseThrow(TlsAlert::noRemoteCipher)
                    .setEnabled(true);
        }
    }
}
