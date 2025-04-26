package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsHandshakeMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.signature.TlsSignature;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;
import static it.auties.leap.tls.util.BufferUtils.readBytesBigEndian16;

public record CertificateVerifyMessage(
        TlsVersion version,
        TlsSource source,
        TlsSignature algorithm,
        byte[] signature
) implements TlsHandshakeMessage {
    private static final int ID = 0x0F;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var signatureAlgorithms = context.getNegotiatedValue(TlsProperty.signatureAlgorithms())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: signatureAlgorithms", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
            var algorithmId = readBigEndianInt16(buffer);
            var algorithm = signatureAlgorithms.get(algorithmId);
            if(algorithm == null) {
                throw new TlsAlert("Certificate verify uses a signature algorithm that wasn't advertised: " + algorithmId, TlsAlertLevel.FATAL, TlsAlertType.UNSUPPORTED_CERTIFICATE);
            }
            var signature = readBytesBigEndian16(buffer);
            return new CertificateVerifyMessage(metadata.version(), metadata.source(), algorithm, signature);
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

    }

    @Override
    public int payloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context) {

    }
}
