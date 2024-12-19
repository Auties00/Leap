package it.auties.leap.tls.message.server;

import it.auties.leap.tls.BufferHelper;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.message.TlsHandshakeMessage;

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.BufferHelper.*;

public final class ServerCertificateRequestMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0D;

    private final List<Byte> types;
    private final List<Integer> algorithms;
    private final List<String> authorities;
    public ServerCertificateRequestMessage(TlsVersion tlsVersion, TlsSource source, List<Byte> types, List<Integer> algorithms, List<String> authorities) {
        super(tlsVersion, source);
        this.types = types;
        this.algorithms = algorithms;
        this.authorities = authorities;
    }

    public static ServerCertificateRequestMessage of(TlsVersion version, TlsSource source, ByteBuffer buffer) {
        var certificatesLength = BufferHelper.readLittleEndianInt8(buffer);
        var certificateTypes = new ArrayList<Byte>();
        try(var _ = scopedRead(buffer, certificatesLength)) {
            while (buffer.hasRemaining()) {
                var certificateTypeId = readLittleEndianInt8(buffer);
                certificateTypes.add(certificateTypeId);
            }
        }

        var algorithmsLength = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<Integer>();
        try(var _ = scopedRead(buffer, algorithmsLength)) {
            while (buffer.hasRemaining()) {
                var algorithmId = readLittleEndianInt16(buffer);
                algorithms.add(algorithmId);
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

    public List<Byte> types() {
        return types;
    }

    public List<Integer> algorithms() {
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
