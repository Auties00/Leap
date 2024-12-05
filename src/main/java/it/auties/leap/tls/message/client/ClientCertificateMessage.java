package it.auties.leap.tls.message.client;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.TlsRecord.*;

public final class ClientCertificateMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0B;

    private final List<X509Certificate> certificates;
    public ClientCertificateMessage(TlsVersion version, Source source, List<X509Certificate> certificates) {
        super(version, source);
        this.certificates = certificates;
    }

    public static ClientCertificateMessage of(TlsVersion version, Source source, ByteBuffer buffer) {
        var certificatesLength = readInt24(buffer);
        try(var _ = scopedRead(buffer, certificatesLength)) {
            var factory = CertificateFactory.getInstance("X.509");
            var certificates = new ArrayList<X509Certificate>();
            while (buffer.hasRemaining()) {
                var certificateSource = readStream24(buffer);
                var certificate = (X509Certificate) factory.generateCertificate(certificateSource);
                certificates.add(certificate);
            }
            return new ClientCertificateMessage(version, source, certificates);
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
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || precedingMessages.getLast() != Type.SERVER_HELLO_DONE) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsEngineMode.CLIENT;
                case REMOTE -> mode == TlsEngineMode.SERVER;
            };
            case UDP -> false;
        };
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {
        writeInt24(buffer, getCertificatesLength());
        for(var certificate : certificates) {
            writeBytes24(buffer, encodeCertificate(certificate));
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
