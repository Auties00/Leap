package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CertificateMessage(
        TlsVersion version,
        TlsSource source,
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
        public TlsHandshakeMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            var certificatesLength = readBigEndianInt24(buffer);
            try(var _ = scopedRead(buffer, certificatesLength)) {
                var certificates = new ArrayList<TlsCertificate>();
                while (buffer.hasRemaining()) {
                    var certificate = readStreamBigEndian24(buffer);
                    certificates.add(TlsCertificate.of(certificate));
                }
                return new CertificateMessage(metadata.version(), metadata.source(), certificates, certificatesLength);
            }
        }
    };

    public CertificateMessage(TlsVersion version, TlsSource source, List<TlsCertificate> certificates) {
        var length = certificates.stream()
                .mapToInt(TlsCertificate::length)
                .sum();
        this(version, source, certificates, length);
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
        writeBigEndianInt24(buffer, certificatesLength);
        for(var certificate : certificates) {
            writeBytesBigEndian24(buffer, certificate.encoded());
        }
    }

    @Override
    public void apply(TlsContext context) {
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        if(negotiatedCipher.authFactory().isAnonymous()) {
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
                        context.connectionInitializer()
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
                        context.connectionInitializer()
                                .initialize(context);
                    }
                }
            }
        }
    }

    @Override
    public int payloadLength() {
        return INT24_LENGTH + certificatesLength;
    }
}
