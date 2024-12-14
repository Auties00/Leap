package it.auties.leap.tls.message.server;

import it.auties.leap.tls.TlsClientCertificateType;
import it.auties.leap.tls.TlsSignatureAlgorithm;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.TlsBuffer;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.TlsBuffer.*;

public final class ServerCertificateRequestMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0D;

    private final List<TlsClientCertificateType> types;
    private final List<TlsSignatureAlgorithm> algorithms;
    private final List<String> authorities;
    public ServerCertificateRequestMessage(TlsVersion tlsVersion, Source source, List<TlsClientCertificateType> types, List<TlsSignatureAlgorithm> algorithms, List<String> authorities) {
        super(tlsVersion, source);
        this.types = types;
        this.algorithms = algorithms;
        this.authorities = authorities;
    }

    public static ServerCertificateRequestMessage of(TlsVersion version, Source source, ByteBuffer buffer) {
        var certificatesLength = TlsBuffer.readLittleEndianInt8(buffer);
        var certificateTypes = new ArrayList<TlsClientCertificateType>();
        try(var _ = scopedRead(buffer, certificatesLength)) {
            while (buffer.hasRemaining()) {
                var certificateTypeId = readLittleEndianInt8(buffer);
                var certificateType = TlsClientCertificateType.of(certificateTypeId)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown tls certificate type: " + certificateTypeId));
                certificateTypes.add(certificateType);
            }
        }

        var algorithmsLength = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<TlsSignatureAlgorithm>();
        try(var _ = scopedRead(buffer, algorithmsLength)) {
            while (buffer.hasRemaining()) {
                var algorithmId = readLittleEndianInt16(buffer);
                var algorithm = switch (version) {
                    case TLS13, DTLS13 -> TlsSignatureAlgorithm.ofTlsV13(algorithmId);
                    case TLS12, DTLS12 -> TlsSignatureAlgorithm.ofTlsV12(algorithmId)
                            .orElseThrow(() -> new IllegalArgumentException("Unknown tls algorithm: " + algorithmId));
                    default -> throw new IllegalArgumentException("Unsupported TLS version: " + version);
                };
                algorithms.add(algorithm);
            }
        }

        var authoritiesLength = readLittleEndianInt16(buffer);
        var authorities = new ArrayList<String>();
        try(var _ = scopedRead(buffer, authoritiesLength)) {
            while (buffer.hasRemaining()) {
                var authority = new X500Principal(readStreamLittleEndian16(buffer));
                authorities.add(authority.getName(X500Principal.CANONICAL));
            }
        }

        return new ServerCertificateRequestMessage(version, source, certificateTypes, algorithms, authorities);
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public Type type() {
        return Type.SERVER_CERTIFICATE_REQUEST;
    }

    @Override
    public boolean isSupported(TlsVersion version, TlsEngineMode mode, Source source, List<Type> precedingMessages) {
        if(precedingMessages.isEmpty() || precedingMessages.getLast() != Type.SERVER_KEY_EXCHANGE) {
            return false;
        }

        return switch (version.protocol()) {
            case TCP -> switch (source) {
                case LOCAL -> mode == TlsEngineMode.SERVER;
                case REMOTE -> mode == TlsEngineMode.CLIENT;
            };
            case UDP -> false;
        };
    }

    public List<TlsClientCertificateType> types() {
        return types;
    }

    public List<TlsSignatureAlgorithm> algorithms() {
        return algorithms;
    }

    public List<String> authorities() {
        return authorities;
    }

    @Override
    public ContentType contentType() {
        return ContentType.HANDSHAKE;
    }

    @Override
    public void serializeHandshakePayload(ByteBuffer buffer) {

    }

    @Override
    public int handshakePayloadLength() {
        return 0;
    }
}
