package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CertificateMessage(
        TlsSource source,
        byte[] requestContext,
        List<TlsCertificate> certificates,
        int certificatesLength
) implements TlsHandshakeMessage {
    private static final byte ID = 0x0B;

    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var version = context.getNegotiatedValue(TlsContextualProperty.version()).orElseThrow(() -> new TlsAlert(
                    "Cannot decode CertificateMessage: no version was negotiated",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.DECODE_ERROR
            ));
            if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
                var requestContext = readBytesBigEndian8(buffer);
                var certificatesLength = readBigEndianInt24(buffer);
                try (var _ = scopedRead(buffer, certificatesLength)) {
                    var certificates = new ArrayList<TlsCertificate>();
                    while (buffer.hasRemaining()) {
                        var certificate = TlsCertificate.of(readStreamBigEndian24(buffer));
                        var extensions = TlsExtension.of(context, readBufferBigEndian16(buffer));
                        certificate.addExtensions(extensions);
                        certificates.add(certificate);
                    }
                    return new CertificateMessage(metadata.source(), requestContext, certificates, certificatesLength);
                }
            } else {
                var certificatesLength = readBigEndianInt24(buffer);
                try (var _ = scopedRead(buffer, certificatesLength)) {
                    var certificates = new ArrayList<TlsCertificate>();
                    while (buffer.hasRemaining()) {
                        var certificate = readStreamBigEndian24(buffer);
                        certificates.add(TlsCertificate.of(certificate));
                    }
                    return new CertificateMessage(metadata.source(), null, certificates, certificatesLength);
                }
            }
        }
    };

    public CertificateMessage(TlsSource source, byte[] requestContext, List<TlsCertificate> certificates) {
        var certificatesLength = certificates.stream()
                .mapToInt(TlsCertificate::length)
                .sum();
        this(source, requestContext, certificates, certificatesLength);
    }

    public CertificateMessage {
        Objects.requireNonNull(source, "Invalid source");
        Objects.requireNonNull(certificates, "Invalid certificates");
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
    public void serializePayload(ByteBuffer buffer) {
        if(requestContext != null) {
            writeBytesBigEndian8(buffer, requestContext);
        }
        writeBigEndianInt24(buffer, certificatesLength);
        for(var certificate : certificates) {
            certificate.serialize(buffer);
        }
    }

    @Override
    public int payloadLength() {
        return INT24_LENGTH + certificates.stream()
                .mapToInt(TlsCertificate::length)
                .sum();
    }
    
    @Override
    public void apply(TlsContext context) {
        var negotiatedCipher = context.getNegotiatedValue(TlsContextualProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if(negotiatedCipher.auth().anonymous()) {
            throw new TlsAlert("Anonymous cipher don't support certificate message", TlsAlertLevel.FATAL, TlsAlertType.UNEXPECTED_MESSAGE);
        }

        var certificate = context.certificateValidator()
                .validate(context, source, certificates);
        switch (source) {
            case LOCAL -> {
                if (negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
                    var keyExchange = negotiatedCipher.keyExchangeFactory()
                            .newLocalKeyExchange(context);
                    context.localConnectionState()
                            .setKeyExchange(keyExchange);
                    if(context.localConnectionState().type() == TlsConnectionType.SERVER) {
                        context.connectionHandler()
                                .initialize(context);
                    }
                }
            }

            case REMOTE -> {
                var remoteConnectionState = context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                remoteConnectionState.addCertificate(certificate);
                if (negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
                    var keyExchange = negotiatedCipher.keyExchangeFactory()
                            .newRemoteKeyExchange(context, null);
                    remoteConnectionState.setKeyExchange(keyExchange);
                    if(remoteConnectionState.type() == TlsConnectionType.SERVER) {
                        context.connectionHandler()
                                .initialize(context);
                    }
                }
            }
        }
    }

    @Override
    public void validate(TlsContext context) {
        var version = context.getNegotiatedValue(TlsContextualProperty.version()).orElseThrow(() -> new TlsAlert(
                "Cannot validate CertificateMessage: no version was negotiated",
                TlsAlertLevel.FATAL,
                TlsAlertType.DECODE_ERROR
        ));
        if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
            if(requestContext == null) {
                throw new IllegalArgumentException("Expected a non-null request context in (D)TLS1.3");
            }

        } else {
            if(requestContext != null) {
                throw new IllegalArgumentException("Expected a null request context in <=(D)TLS1.2");
            }
            if(certificates.stream().anyMatch(TlsCertificate::hasExtensions)) {
                throw new IllegalArgumentException("Certificate extensions are not supported in <=(D)TLS1.2");
            }
        }
    }

    @Override
    public boolean hashable() {
        return true;
    }
}
