package it.auties.leap.tls.message.server;

import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class ServerCertificateMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0B;

    private final List<X509Certificate> certificates;
    public ServerCertificateMessage(TlsVersion version, TlsSource source, List<X509Certificate> certificates) {
        super(version, source);
        this.certificates = certificates;
    }

    public static ServerCertificateMessage of(TlsVersion version, TlsSource source, ByteBuffer buffer) {
        var certificatesLength = readLittleEndianInt24(buffer);
        try(var _ = scopedRead(buffer, certificatesLength)) {
            var factory = CertificateFactory.getInstance("X.509");
            var certificates = new ArrayList<X509Certificate>();
            while (buffer.hasRemaining()) {
                var certificateSource = readStreamLittleEndian24(buffer);
                var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                certificates.add(certificate);
            }
            return new ServerCertificateMessage(version, source, certificates);
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
        writeLittleEndianInt24(buffer, getCertificatesLength());
        for(var certificate : certificates) {
            writeBytesLittleEndian24(buffer, encodeCertificate(certificate));
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
