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

public sealed abstract class CertificateMessage extends TlsHandshakeMessage {
    private static final byte ID = 0x0B;
    private static final TlsMessageDeserializer DESERIALIZER = new TlsMessageDeserializer() {
        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
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
                    return new Client(metadata.version(),  certificates);
                }catch (CertificateException exception) {
                    throw new RuntimeException("Cannot parse X509 certificate", exception);
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
                    return new Server(metadata.version(), metadata.source(), certificates);
                }catch (CertificateException exception) {
                    throw new RuntimeException("Cannot parse X509 certificate", exception);
                }
            }
        }
    };

    CertificateMessage(TlsVersion version) {
        super(version);
    }

    CertificateMessage(TlsContext context) {
        super(context);
    }

    public static TlsMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    public static final class Client extends CertificateMessage {
        private final List<X509Certificate> certificates;

        private Client(TlsVersion version, List<X509Certificate> certificates) {
            super(version);
            this.certificates = certificates;
        }

        public Client(TlsContext context) {
            super(context);
            this.certificates = context.certificatesProvider()
                    .orElseThrow(TlsAlert::noCertificatesProvider)
                    .get(context);
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
            writeBigEndianInt24(buffer, getCertificatesLength());
            for(var certificate : certificates) {
                writeBytesBigEndian24(buffer, encodeCertificate(certificate));
            }
        }

        @Override
        public void apply(TlsContext context) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsAlert("No mode was selected yet"));
            switch (mode) {
                case CLIENT -> context.localConnectionState()
                        .setCertificates(certificates);
                case SERVER -> context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote credentials"))
                        .setCertificates(certificates);
            }
        }

        @Override
        public int handshakePayloadLength() {
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
                throw new RuntimeException("Cannot encode X509 certificate", exception);
            }
        }
    }

    public static final class Server extends CertificateMessage {
        private final List<X509Certificate> certificates;
        public Server(TlsVersion version, TlsSource source, List<X509Certificate> certificates) {
            super(version, source);
            this.certificates = certificates;
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
            writeBigEndianInt24(buffer, getCertificatesLength());
            for(var certificate : certificates) {
                writeBytesBigEndian24(buffer, encodeCertificate(certificate));
            }
        }

        @Override
        public int handshakePayloadLength() {
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
                throw new RuntimeException("Cannot encode X509 certificate", exception);
            }
        }

        @Override
        public void apply(TlsContext context) {
            var mode = context.selectedMode()
                    .orElseThrow(() -> new TlsAlert("No mode was selected yet"));
            switch (mode) {
                case CLIENT -> context.remoteConnectionState()
                        .orElseThrow(() -> new TlsAlert("No remote credentials"))
                        .setCertificates(certificates);
                case SERVER -> context.localConnectionState()
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
}
