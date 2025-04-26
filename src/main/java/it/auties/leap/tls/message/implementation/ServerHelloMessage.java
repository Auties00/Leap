package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.connection.TlsHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsHandshakeMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ServerHelloMessage(
        TlsVersion version,
        TlsSource source,
        byte[] randomData,
        byte[] sessionId,
        int cipher,
        byte compression,
        List<? extends TlsExtension.Configured.Server> extensions,
        int extensionsLength
) implements TlsHandshakeMessage {
    private static final int SERVER_RANDOM_LENGTH = 32;
    private static final int SESSION_ID_LENGTH = 32;
    private static final byte ID = 0x02;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var tlsVersionId = readBigEndianInt16(buffer);
            var tlsVersion = TlsVersion.of(tlsVersionId)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

            var serverRandom = readBytes(buffer, SERVER_RANDOM_LENGTH);

            var sessionId = readBytesBigEndian8(buffer);

            var cipherId = readBigEndianInt16(buffer);

            var compressionId = readBigEndianInt8(buffer);

            var extensionTypeToDecoder = context.getNegotiatedValue(TlsProperty.clientExtensions())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: clientExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsExtension::type, Function.identity()));
            var extensions = new ArrayList<TlsExtension.Configured.Server>();
            var extensionsLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
            try (var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readBigEndianInt16(buffer);
                    var extensionDecoder = extensionTypeToDecoder.get(extensionType);
                    if (extensionDecoder == null) {
                        throw new TlsAlert("Unknown extension", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var extensionLength = readBigEndianInt16(buffer);
                    try (var _ = scopedRead(buffer, extensionLength)) {
                        extensionDecoder.deserialize(context, extensionType, buffer)
                                .ifPresent(extensions::add);
                    }
                }
            }

            return new ServerHelloMessage(tlsVersion, metadata.source(), serverRandom, sessionId, cipherId, compressionId, extensions, extensionsLength);
        }
    };

    public ServerHelloMessage {
        if(randomData == null || randomData.length != SERVER_RANDOM_LENGTH) {
            throw new TlsAlert("Invalid random data length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(sessionId == null || sessionId.length != SESSION_ID_LENGTH) {
            throw new TlsAlert("Invalid session id length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(extensions == null) {
            throw new TlsAlert("Invalid extensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
    }

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
    public void serializePayload(ByteBuffer payload) {
        version.serialize(payload);

        writeBytes(payload, randomData);

        writeBytesBigEndian8(payload, sessionId);

        writeBigEndianInt16(payload, cipher);

        writeBigEndianInt8(payload, compression);

        if (!extensions.isEmpty()) {
            writeBigEndianInt16(payload, extensionsLength);
            for (var extension : extensions) {
                extension.serialize(payload);
            }
        }
    }

    @Override
    public int payloadLength() {
        return version.length()
                + SERVER_RANDOM_LENGTH
                + INT8_LENGTH + SESSION_ID_LENGTH
                + INT16_LENGTH
                + INT8_LENGTH
                + (extensions.isEmpty() ? 0 : INT16_LENGTH + extensionsLength);
    }

    @Override
    public void apply(TlsContext context) {
        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_STARTED);

            case REMOTE -> {
                var credentials = TlsConnection.of(TlsConnectionType.SERVER, randomData, sessionId, null);
                credentials.setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_STARTED);
                context.setRemoteConnectionState(credentials);

                var negotiatedCipher = context.getNegotiableValue(TlsProperty.cipher())
                        .orElseThrow(() -> new TlsAlert("Missing negotiable property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .stream()
                        .filter(entry -> entry.id() == cipher)
                        .findFirst()
                        .orElseThrow(() -> new TlsAlert("Remote negotiated a cipher that wasn't available", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                context.addNegotiatedProperty(TlsProperty.cipher(), negotiatedCipher);

                var negotiatedCompression = context.getNegotiableValue(TlsProperty.compression())
                        .orElseThrow(() -> new TlsAlert("Missing negotiable property: compression", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .stream()
                        .filter(entry -> entry.id() == compression)
                        .findFirst()
                        .orElseThrow(() -> new TlsAlert("Remote negotiated a compression that wasn't available", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                context.addNegotiatedProperty(TlsProperty.compression(), negotiatedCompression);

                for (var extension : extensions) {
                    context.addProcessedExtension(extension.type());
                    extension.apply(context, source);
                }

                var version = context.getNegotiatedValue(TlsProperty.version()).orElseGet(() -> {
                    context.addNegotiatedProperty(TlsProperty.version(), this.version); // supported_versions extension wasn't in the extensions list, default to legacyVersion
                    return this.version;
                });

                context.connectionHandshakeHash()
                        .init(version, negotiatedCipher.hashFactory());

                if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
                    if(negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
                        throw new TlsAlert("Static key exchange not supported", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var localKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(context);
                    context.localConnectionState()
                            .setKeyExchange(localKeyExchange);
                    var remoteKeyExchange = negotiatedCipher.keyExchangeFactory()
                            .newRemoteKeyExchange(context, null);
                    context.remoteConnectionState()
                            .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                            .setKeyExchange(remoteKeyExchange);
                    context.connectionInitializer()
                            .initialize(context);
                }else {
                    context.getNegotiatedValue(TlsProperty.clientExtensions())
                            .orElseThrow(() -> new TlsAlert("Missing negotiated property: clientExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                            .stream()
                            .filter(entry -> !context.hasProcessedExtension(entry.type()))
                            .forEach(entry -> entry.apply(context, source));
                }
            }
        }
    }
}
