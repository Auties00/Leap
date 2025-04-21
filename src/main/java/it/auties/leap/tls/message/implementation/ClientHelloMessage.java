package it.auties.leap.tls.message.implementation;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.connection.TlsHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ClientHelloMessage(
        TlsVersion version,
        TlsSource source,
        byte[] randomData,
        byte[] sessionId,
        byte[] cookie,
        List<Integer> ciphers,
        List<Byte> compressions,
        List<TlsExtension.Configured.Client> extensions,
        int extensionsLength
) implements TlsHandshakeMessage {
    private static final int ID = 0x01;
    private static final int CLIENT_RANDOM_LENGTH = 32;
    private static final int SESSION_ID_LENGTH = 32;
    private static final int RANDOM_COOKIE_LENGTH = 32;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var versionId = TlsVersionId.of(readBigEndianInt16(buffer));
            var tlsVersion = TlsVersion.of(versionId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
            var clientRandom = readBytes(buffer, CLIENT_RANDOM_LENGTH);
            var sessionId = readBytesBigEndian8(buffer);
            var cookie = switch (metadata.version().protocol()) {
                case TCP -> null;
                case UDP -> readBytesBigEndian8(buffer);
            };
            var ciphersLength = readBigEndianInt16(buffer);
            var ciphers = new ArrayList<Integer>();
            try (var _ = scopedRead(buffer, ciphersLength)) {
                while (buffer.hasRemaining()) {
                    var cipherId = readBigEndianInt16(buffer);
                    ciphers.add(cipherId);
                }
            }
            var compressions = new ArrayList<Byte>();
            var compressionsLength = readBigEndianInt16(buffer);
            try (var _ = scopedRead(buffer, compressionsLength)) {
                while (buffer.hasRemaining()) {
                    var compressionId = readBigEndianInt8(buffer);
                    compressions.add(compressionId);
                }
            }
            var extensions = new ArrayList<TlsExtension.Configured.Client>();
            var extensionsLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
            try (var _ = scopedRead(buffer, extensionsLength)) {
                var extensionTypeToDecoder = context.getNegotiatedValue(TlsProperty.serverExtensions())
                        .orElseThrow(() -> new TlsAlert("Missing negotiated property: serverExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                        .stream()
                        .collect(Collectors.toUnmodifiableMap(TlsExtension::type, Function.identity()));
                while (buffer.hasRemaining()) {
                    var extensionType = readBigEndianInt16(buffer);
                    var extensionDecoder = extensionTypeToDecoder.get(extensionType);
                    if (extensionDecoder == null) {
                        throw new TlsAlert("Unknown extension", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var extensionLength = readBigEndianInt16(buffer);
                    if (extensionLength == 0) {
                        continue;
                    }

                    try(var _ = scopedRead(buffer, extensionLength)) {
                        extensionDecoder.deserialize(context, extensionType, buffer)
                                .ifPresent(extensions::add);
                    }
                }
            }
            return new ClientHelloMessage(tlsVersion, metadata.source(), clientRandom, sessionId, cookie, ciphers, compressions, extensions, extensionsLength);
        }
    };

    public ClientHelloMessage {
        if(randomData == null || randomData.length != CLIENT_RANDOM_LENGTH) {
            throw new TlsAlert("Invalid random data length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(sessionId == null || sessionId.length != SESSION_ID_LENGTH) {
            throw new TlsAlert("Invalid session id length", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if((version.protocol() == SocketProtocol.UDP) == (cookie == null)) {
            throw new TlsAlert("Invalid dtls cookie", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(ciphers == null || ciphers.isEmpty()) {
            throw new TlsAlert("Invalid ciphers", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(compressions == null || compressions.isEmpty()) {
            throw new TlsAlert("Invalid compressions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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

        if (cookie != null) {
            writeBytesBigEndian8(payload, cookie);
        }

        var ciphersLength = ciphers.size() * INT16_LENGTH;
        writeBigEndianInt16(payload, ciphersLength);
        for (var cipher : ciphers) {
            writeBigEndianInt16(payload, cipher);
        }

        var compressionsLength = compressions.size() * INT8_LENGTH;
        writeBigEndianInt8(payload, compressionsLength);
        for (var compression : compressions) {
            writeBigEndianInt8(payload, compression);
        }

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
                + CLIENT_RANDOM_LENGTH
                + INT8_LENGTH + SESSION_ID_LENGTH
                + (cookie != null ? INT8_LENGTH + RANDOM_COOKIE_LENGTH : 0)
                + INT16_LENGTH + ciphers.size() * INT16_LENGTH
                + INT8_LENGTH + compressions.size() * INT8_LENGTH
                + (extensions.isEmpty() ? 0 : INT16_LENGTH + extensionsLength);
    }

    @Override
    public void apply(TlsContext context) {
        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_DONE);
            case REMOTE -> {
                var credentials = TlsConnection.newConnection(TlsConnectionType.CLIENT, randomData, sessionId, cookie);
                credentials.setHandshakeStatus(TlsHandshakeStatus.HANDSHAKE_DONE);
                context.setRemoteConnectionState(credentials);

                var negotiatedCipher = chooseCipher(context);

                chooseCompression(context);

                for(var extension : extensions) {
                    extension.apply(context, source);
                }

                context.connectionIntegrity()
                        .init(version, negotiatedCipher.hashFactory());
            }
        }
    }

    private TlsCipherSuite chooseCipher(TlsContext context) {
        var negotiableCiphers = context.getNegotiableValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: " + TlsProperty.cipher().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsCipherSuite::id, Function.identity()));
        for(var advertisedCipherId : ciphers) {
            var advertisedCipher = negotiableCiphers.get(advertisedCipherId);
            if(advertisedCipher != null) {
                context.addNegotiatedProperty(TlsProperty.cipher(), advertisedCipher);
                return advertisedCipher;
            }
        }
        throw new TlsAlert("None of the advertised ciphers are supported or enabled", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
    }

    private void chooseCompression(TlsContext context) {
        var negotiableCompressions = context.getNegotiableValue(TlsProperty.compression())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: " + TlsProperty.compression().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsCompression::id, Function.identity()));
        for(var advertisedCompressionId : compressions) {
            var advertisedCompression = negotiableCompressions.get(advertisedCompressionId);
            if(advertisedCompression != null) {
                context.addNegotiatedProperty(TlsProperty.compression(), advertisedCompression);
                return;
            }
        }
        throw new TlsAlert("None of the advertised compressions are supported or enabled", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
    }
}
