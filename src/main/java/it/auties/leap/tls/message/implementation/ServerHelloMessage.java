package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
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
    private static final int RANDOM_COOKIE_LENGTH = 32;
    public static final byte ID = 0x02;

    public static ServerHelloMessage of(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        var tlsVersionId = readBigEndianInt16(buffer);
        var tlsVersion = TlsVersion.of(tlsVersionId)
                .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

        var serverRandom = readBytes(buffer, SERVER_RANDOM_LENGTH);

        var sessionId = readBytesBigEndian8(buffer);

        var cipherId = readBigEndianInt16(buffer);

        var compressionId = readBigEndianInt8(buffer);

        var extensionTypeToDecoder = context.getNegotiatedValue(TlsProperty.clientExtensions())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.clientExtensions()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsExtension::type, Function.identity()));
        var extensions = new ArrayList<TlsExtension.Configured.Server>();
        var extensionsLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
        try (var _ = scopedRead(buffer, extensionsLength)) {
            while (buffer.hasRemaining()) {
                var extensionType = readBigEndianInt16(buffer);
                var extensionDecoder = extensionTypeToDecoder.get(extensionType);
                if (extensionDecoder == null) {
                    throw new TlsAlert("Unknown extension");
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

    }

    @Override
    public void apply(TlsContext context) {
        var credentials = TlsConnection.of(randomData, sessionId, null);
        context.setRemoteConnectionState(credentials);

        var negotiatedCipher = context.getNegotiableValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.cipher()))
                .stream()
                .filter(entry -> entry.id() == cipher)
                .findFirst()
                .orElseThrow(() -> new TlsAlert("Remote negotiated a cipher that wasn't available"));
        context.addNegotiatedProperty(TlsProperty.cipher(), negotiatedCipher);

        var negotiatedCompression = context.getNegotiableValue(TlsProperty.compression())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.compression()))
                .stream()
                .filter(entry -> entry.id() == compression)
                .findFirst()
                .orElseThrow(() -> new TlsAlert("Remote negotiated a compression that wasn't available"));
        context.addNegotiatedProperty(TlsProperty.compression(), negotiatedCompression);

        var seen = new HashSet<Integer>();
        for (var extension : extensions) {
            seen.add(extension.type());
            extension.apply(context, source);
        }

        var version = context.getNegotiatedValue(TlsProperty.version()).orElseGet(() -> {
            context.addNegotiatedProperty(TlsProperty.version(), this.version); // supported_versions extension wasn't in the extensions list, default to legacyVersion
            return this.version;
        });

        if(context.mode() == TlsContextMode.CLIENT && version.id().value() <= TlsVersion.DTLS12.id().value()) {
            context.getNegotiatedValue(TlsProperty.clientExtensions())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.clientExtensions()))
                    .stream()
                    .filter(entry -> !seen.contains(entry.type()))
                    .forEach(entry -> entry.apply(context, source));
        }

        context.connectionIntegrity()
                .init(version, negotiatedCipher.hashFactory());
    }

    @Override
    public int payloadLength() {
        return 0;
    }
}
