package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class CertificateMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0B;

    CertificateMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Client extends CertificateMessage {
        private final List<X509Certificate> certificates;
        public Client(TlsVersion version, TlsSource source, List<X509Certificate> certificates) {
            super(version, source);
            this.certificates = certificates;
        }

        public static Client of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
            var certificatesLength = readBigEndianInt24(buffer);
            try(var _ = scopedRead(buffer, certificatesLength)) {
                var factory = CertificateFactory.getInstance("X.509");
                var certificates = new ArrayList<X509Certificate>();
                while (buffer.hasRemaining()) {
                    var certificateSource = readStreamBigEndian24(buffer);
                    var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                    certificates.add(certificate);
                }
                return new Client(metadata.version(), metadata.source(), certificates);
            }catch (CertificateException exception) {
                throw new RuntimeException("Cannot parse X509 certificate", exception);
            }
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.CLIENT_CERTIFICATE;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBigEndianInt24(buffer, getCertificatesLength());
            for(var certificate : certificates) {
                writeBytesBigEndian24(buffer, encodeCertificate(certificate));
            }
        }

        public List<X509Certificate> certificates() {
            return certificates;
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

        public static Server of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
            var certificatesLength = readBigEndianInt24(buffer);
            try(var _ = scopedRead(buffer, certificatesLength)) {
                var factory = CertificateFactory.getInstance("X.509");
                var certificates = new ArrayList<X509Certificate>();
                while (buffer.hasRemaining()) {
                    var certificateSource = readStreamBigEndian24(buffer);
                    try {
                        System.out.println("Remaining: " + certificateSource.available());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                    certificates.add(certificate);
                }
                return new Server(metadata.version(), metadata.source(), certificates);
            }catch (CertificateException exception) {
                throw new RuntimeException("Cannot parse X509 certificate", exception);
            }
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.SERVER_CERTIFICATE;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {
            writeBigEndianInt24(buffer, getCertificatesLength());
            for(var certificate : certificates) {
                writeBytesBigEndian24(buffer, encodeCertificate(certificate));
            }
        }

        public List<X509Certificate> certificates() {
            return certificates;
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
}
