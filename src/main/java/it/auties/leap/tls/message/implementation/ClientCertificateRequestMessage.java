package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public record ClientCertificateRequestMessage(
        TlsVersion version,
        TlsSource source,
        List<Byte> types,
        List<Integer> algorithms,
        List<String> authorities
) implements TlsHandshakeMessage {
    public static final byte ID = 0x0D;

    public static ClientCertificateRequestMessage of(ByteBuffer buffer, TlsMessageMetadata metadata) {
        var certificatesLength = readBigEndianInt8(buffer);
        var certificateTypes = new ArrayList<Byte>();
        try(var _ = scopedRead(buffer, certificatesLength)) {
            while (buffer.hasRemaining()) {
                var certificateTypeId = readBigEndianInt8(buffer);
                certificateTypes.add(certificateTypeId);
            }
        }

        var algorithmsLength = readBigEndianInt16(buffer);
        var algorithms = new ArrayList<Integer>();
        try(var _ = scopedRead(buffer, algorithmsLength)) {
            while (buffer.hasRemaining()) {
                var algorithmId = readBigEndianInt16(buffer);
                algorithms.add(algorithmId);
            }
        }

        var authoritiesLength = readBigEndianInt16(buffer);
        var authorities = new ArrayList<String>();
        try(var _ = scopedRead(buffer, authoritiesLength)) {
            while (buffer.hasRemaining()) {
                var authority = new X500Principal(readStreamBigEndian16(buffer));
                authorities.add(authority.getName(X500Principal.CANONICAL));
            }
        }

        return new ClientCertificateRequestMessage(metadata.version(), metadata.source(), certificateTypes, algorithms, authorities);
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

    }

    @Override
    public void apply(TlsContext context) {

    }

    @Override
    public int payloadLength() {
        return 0;
    }
}
