package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record CertificateMessage(
        TlsVersion version,
        TlsSource source,
        List<X509Certificate> certificates
) implements TlsHandshakeMessage {
    public static final byte ID = 0x0B;

    public static CertificateMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        var certificatesLength = readBigEndianInt24(buffer);
        try(var _ = scopedRead(buffer, certificatesLength)) {
            var factory = CertificateFactory.getInstance("X.509");
            var certificates = new ArrayList<X509Certificate>();
            while (buffer.hasRemaining()) {
                var certificateSource = readStreamBigEndian24(buffer);
                var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                certificates.add(certificate);
            }
            return new CertificateMessage(metadata.version(), metadata.source(), certificates);
        }catch (CertificateException exception) {
            throw TlsAlert.certificateError(exception);
        }
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
        writeBigEndianInt24(buffer, getCertificatesLength());
        for(var certificate : certificates) {
            writeBytesBigEndian24(buffer, encodeCertificate(certificate));
        }
    }

    @Override
    public void apply(TlsContext context) {
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
        var certificate = context.certificateStore()
                .validator()
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
                        .orElseThrow(TlsAlert::noRemoteConnectionState);
                remoteConnectionState.setStaticCertificate(certificate);
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
        var certificatesLength = getCertificatesLength();
        return INT24_LENGTH + certificatesLength;
    }

    private int getCertificatesLength() {
        return certificates.stream()
                .mapToInt(buffer -> encodeCertificate(buffer).length + INT24_LENGTH)
                .sum();
    }

    private static byte[] encodeCertificate(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        }catch (CertificateEncodingException exception) {
            throw TlsAlert.certificateError(exception);
        }
    }
}
