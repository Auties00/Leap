package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
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
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var remoteParameters = context.getNegotiatedValue(TlsProperty.cipher())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()))
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
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
        if (negotiatedCipher.keyExchangeFactory().type() != TlsKeyExchangeType.EPHEMERAL) {
            throw new TlsAlert("Unexpected server key exchange message for static key exchange");
        }

        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setKeyExchange(parameters);
            case REMOTE -> {
                context.remoteConnectionState()
                        .orElseThrow(TlsAlert::noRemoteConnectionState)
                        .setKeyExchange(parameters);
                var localKeyExchange = negotiatedCipher.keyExchangeFactory()
                        .newLocalKeyExchange(context);
                context.localConnectionState()
                        .setKeyExchange(localKeyExchange);
            }
        }
    }
}
