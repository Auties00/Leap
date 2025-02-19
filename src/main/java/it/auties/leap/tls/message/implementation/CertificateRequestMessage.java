package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;

import javax.security.auth.x500.X500Principal;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class CertificateRequestMessage extends TlsHandshakeMessage {
    public static final byte ID = 0x0D;

    CertificateRequestMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Server extends CertificateRequestMessage {
        private final List<Byte> types;
        private final List<Integer> algorithms;
        private final List<String> authorities;
        public Server(TlsVersion tlsVersion, TlsSource source, List<Byte> types, List<Integer> algorithms, List<String> authorities) {
            super(tlsVersion, source);
            this.types = types;
            this.algorithms = algorithms;
            this.authorities = authorities;
        }

        public static Server of(TlsContext ignoredEngine, ByteBuffer buffer, Metadata metadata) {
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

            return new Server(metadata.version(), metadata.source(), certificateTypes, algorithms, authorities);
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
}
