package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateCompressionAlgorithm;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CompressedCertificateMessage(
        TlsVersion version,
        TlsSource source,
        TlsCertificateCompressionAlgorithm algorithm,
        int compressedLength,
        byte[] compressedCertificateMessage
) implements TlsHandshakeMessage {
    private static final byte ID = 0x19;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var negotiatedAlgorithms = context.getNegotiatedValue(TlsProperty.certificateCompressionAlgorithms())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: certificateCompressionAlgorithms", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
            var algorithmId = readBigEndianInt16(buffer);
            var algorithm = negotiatedAlgorithms.get(algorithmId);
            if(algorithm == null) {
                throw new TlsAlert("Remote tried to send a compressed certificate using a compression algorithm that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            var compressedLength = readBigEndianInt16(buffer);
            var compressedCertificateMessage = readBytesBigEndian24(buffer);
            return new CompressedCertificateMessage(metadata.version(), metadata.source(), algorithm, compressedLength, compressedCertificateMessage);
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
        writeBigEndianInt16(buffer, algorithm.id());
        writeBigEndianInt16(buffer, compressedLength);
        writeBytesBigEndian24(buffer, compressedCertificateMessage);
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH
                + INT16_LENGTH
                + INT24_LENGTH;
    }

    @Override
    public void apply(TlsContext context) {

    }
}
