package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ServerKeyExchangeMessage(
        TlsVersion version,
        TlsSource source,
        TlsKeyExchange parameters,
        int signatureAlgorithm,
        byte[] signature
) implements TlsHandshakeMessage {
    private static final byte ID = 0x0C;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var remoteParameters = context.getNegotiatedValue(TlsContextualProperty.cipher())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .keyExchangeFactory()
                    .newRemoteKeyExchange(context, buffer);
            var signatureAlgorithmId = readBigEndianInt16(buffer);
            var signature = readBytesBigEndian16(buffer);
            return new ServerKeyExchangeMessage(metadata.version(), metadata.source(), remoteParameters, signatureAlgorithmId, signature);
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
        writeBigEndianInt16(buffer, signatureAlgorithm);
        writeBytesBigEndian16(buffer, signature);
    }

    @Override
    public int payloadLength() {
        return parameters.length()
                + INT16_LENGTH
                + INT16_LENGTH
                + signature.length;
    }

    @Override
    public void apply(TlsContext context) {
        var negotiatedCipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if (negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
            throw new TlsAlert("Unexpected server key exchange message for static key exchange", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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
    }

    @Override
    public boolean hashable() {
        return true;
    }

    public void validate(TlsContext context) {

    }
}
