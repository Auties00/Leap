package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt24;
import static it.auties.leap.tls.util.BufferUtils.scopedRead;

public record ClientKeyExchangeMessage(
        TlsVersion version,
        TlsSource source,
        TlsKeyExchange parameters
) implements TlsHandshakeMessage {
    private static final byte ID = 0x10;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var messageLength = readBigEndianInt24(buffer);
            try (var _ = scopedRead(buffer, messageLength)) {
                var remoteParameters = context.getNegotiatedValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("No cipher was negotiated", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .keyExchangeFactory()
                        .newRemoteKeyExchange(context, buffer);
                return new ClientKeyExchangeMessage(metadata.version(), metadata.source(), remoteParameters);
            }
        }
    };

    public static TlsHandshakeMessageDeserializer deserializer() {
        return DESERIALIZER;
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
        parameters.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return parameters.length();
    }

    @Override
    public void apply(TlsContext context) {
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("No cipher was negotiated", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if (negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
            throw new TlsAlert("Unexpected client key exchange message for static key exchange", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setKeyExchange(parameters);
            case REMOTE -> {
                context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .setKeyExchange(parameters);
                var localKeyExchange = negotiatedCipher.keyExchangeFactory()
                        .newLocalKeyExchange(context);
                context.localConnectionState()
                        .setKeyExchange(localKeyExchange);
            }
        }

        context.connectionInitializer()
                .initialize(context);
    }
}
