package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ChangeCipherSpecMessage(
        TlsVersion version,
        TlsSource source
) implements TlsMessage {
    public static final int ID = 0x01;

    public static ChangeCipherSpecMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        var id = readBigEndianInt8(buffer);
        if(id != ChangeCipherSpecMessage.ID) {
            throw new TlsAlert("Invalid cipher spec");
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
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, ID);
    }

    @Override
    public int length() {
        return INT8_LENGTH;
    }

    @Override
    public void apply(TlsContext context) {
        try {
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
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}
