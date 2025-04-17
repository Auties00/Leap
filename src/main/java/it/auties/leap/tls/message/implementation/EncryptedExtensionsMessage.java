package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record EncryptedExtensionsMessage(
        TlsVersion version,
        TlsSource source,
        List<TlsExtension.Configured.Server> extensions,
        int extensionsLength
) implements TlsHandshakeMessage {
    private static final byte ID = 0x08;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var extensionTypeToDecoder = context.getNegotiatedValue(TlsProperty.clientExtensions())
                    .orElseThrow(() -> {
                        throw new TlsAlert("Missing negotiated property: " + TlsProperty.clientExtensions().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    })
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
            return new EncryptedExtensionsMessage(metadata.version(), metadata.source(), extensions, extensionsLength);
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
    public void serializePayload(ByteBuffer payload) {
        if (!extensions.isEmpty()) {
            writeBigEndianInt16(payload, extensionsLength);
            for (var extension : extensions) {
                extension.serialize(payload);
            }
        }
    }

    @Override
    public int payloadLength() {
        return (extensions.isEmpty() ? 0 : INT16_LENGTH + extensionsLength);
    }


    @Override
    public void apply(TlsContext context) {

    }
}
