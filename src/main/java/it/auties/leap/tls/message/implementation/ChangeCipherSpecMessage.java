package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ChangeCipherSpecMessage(
        TlsVersion version,
        TlsSource source
) implements TlsMessage {
    private static final int ID = 0x01;
    private static final TlsMessageDeserializer DESERIALIZER = (_, buffer, metadata) -> {
        var id = readBigEndianInt8(buffer);
        if(id != ChangeCipherSpecMessage.ID) {
            throw new TlsAlert("Invalid cipher spec", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var message = new ChangeCipherSpecMessage(metadata.version(), metadata.source());
        return Optional.of(message);
    };

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
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
        var version = context.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
            return;
        }

        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .cipher()
                    .orElseThrow(() -> new TlsAlert("No local cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .setEnabled(true);
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .cipher()
                    .orElseThrow(() -> new TlsAlert("No remote cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .setEnabled(true);
        }
    }
}
