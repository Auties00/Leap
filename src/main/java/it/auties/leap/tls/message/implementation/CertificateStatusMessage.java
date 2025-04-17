package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.certificate.status.TlsCertificateStatusRequest;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public record CertificateStatusMessage(
        TlsVersion version,
        TlsSource source,
        TlsCertificateStatusRequest request
) implements TlsHandshakeMessage {
    private static final byte ID = 0x16;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var request = TlsCertificateStatusRequest.of(buffer)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid certificate request"));
            return new CertificateStatusMessage(metadata.version(), metadata.source(), request);
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
        request.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return request.length();
    }

    @Override
    public void apply(TlsContext context) {

    }
}
