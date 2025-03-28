package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
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

public final class CertificateMessage extends TlsHandshakeMessage {
    private static final byte ID = 0x0B;

    private static final TlsMessageDeserializer DESERIALIZER = (context, buffer, metadata) -> {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        var certificatesLength = readBigEndianInt24(buffer);
        if(mode == TlsContextMode.CLIENT && metadata.source() == TlsSource.LOCAL || mode == TlsContextMode.SERVER && metadata.source() == TlsSource.REMOTE) {
            try(var _ = scopedRead(buffer, certificatesLength)) {
                var factory = CertificateFactory.getInstance("X.509");
                var certificates = new ArrayList<X509Certificate>();
                while (buffer.hasRemaining()) {
                    var certificateSource = readStreamBigEndian24(buffer);
                    var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                    certificates.add(certificate);
                }
                return new CertificateMessage(metadata.version(), metadata.source(), certificates, certificatesLength);
            }catch (CertificateException exception) {
                throw TlsAlert.certificateError(exception);
            }
        }else {
            try(var _ = scopedRead(buffer, certificatesLength)) {
                var factory = CertificateFactory.getInstance("X.509");
                var certificates = new ArrayList<X509Certificate>();
                while (buffer.hasRemaining()) {
                    var certificateSource = readStreamBigEndian24(buffer);
                    var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                    certificates.add(certificate);
                }
                return new CertificateMessage(metadata.version(), metadata.source(), certificates, certificatesLength);
            }catch (CertificateException exception) {
                throw TlsAlert.certificateError(exception);
            }
        }
    };

    private final List<X509Certificate> certificates;
    private final int certificatesLength;
    private CertificateMessage(TlsVersion version, TlsSource source, List<X509Certificate> certificates, int certificatesLength) {
        super(version, source);
        this.certificates = certificates;
        this.certificatesLength = certificatesLength;
    }

    public static CertificateMessage of(TlsContext context) {
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        return switch (mode) {
            case CLIENT -> new Client();
            case SERVER -> new Server();
        };
    }

    public static TlsMessageDeserializer deserializer() {
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
    public void serializeHandshakePayload(ByteBuffer buffer) {
        writeBigEndianInt24(buffer, certificatesLength);
        for(var certificate : certificates) {
            try {
                writeBytesBigEndian24(buffer, certificate.getEncoded());
            }catch (CertificateEncodingException exception) {
                throw TlsAlert.certificateError(exception);
            }
        }
    }

    @Override
    public int handshakePayloadLength() {
        return INT24_LENGTH + certificatesLength;
    }

    @Override
    public void apply(TlsContext context) {
        if(source == TlsSource.REMOTE) {
            context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .setCertificates(certificates);
        }

        switch (source) {
            case LOCAL -> context.localConnectionState()
                    .setCertificates(certificates);
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState)
                    .setCertificates(certificates);
        }
        var negotiatedCipher = context.getNegotiatedValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.cipher()));
        if(negotiatedCipher.keyExchangeFactory().type() == TlsKeyExchangeType.STATIC) {
            var keyExchange = negotiatedCipher.keyExchangeFactory()
                    .newLocalKeyExchange(context);
            context.localConnectionState()
                    .setKeyExchange(keyExchange);
        }
    }
}
