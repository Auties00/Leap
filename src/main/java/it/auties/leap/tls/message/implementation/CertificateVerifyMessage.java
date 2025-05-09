package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.context.TlsContextualProperty;
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
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var signatureAlgorithms = context.getNegotiatedValue(TlsContextualProperty.signatureAlgorithms())
                    .orElseThrow(() -> new TlsAlert(
                            "Cannot decode CertificateVerifyMessage: no signature algorithms were negotiated",
                            TlsAlertLevel.FATAL,
                            TlsAlertType.DECODE_ERROR
                    ))
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsSignature::id, Function.identity()));
            var algorithmId = readBigEndianInt16(buffer);
            var algorithm = signatureAlgorithms.get(algorithmId);
            if(algorithm == null) {
                throw new TlsAlert(
                        "Certificate verify uses a signature algorithm that wasn't negotiated: " + algorithmId,
                        TlsAlertLevel.FATAL,
                        TlsAlertType.UNSUPPORTED_CERTIFICATE
                );
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

    @Override
    public boolean hashable() {
        return true;
    }

    public void validate(TlsContext context) {

    }
}
