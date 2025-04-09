package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsTrustedAuthority extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static TlsTrustedAuthority preAgreed() {
        return PreAgreed.INSTANCE;
    }

    static TlsTrustedAuthority keySha1Hash(byte[] hash) {
        if(hash == null || hash.length != TlsHashFactory.sha1().length()) {
            throw new IllegalArgumentException("Invalid hash");
        }

        return new KeySha1Hash(hash);
    }

    static TlsTrustedAuthority x509Name(byte[] name) {
        if(name == null) {
            throw new IllegalArgumentException("Invalid name");
        }

        return new X509Name(name);
    }

    static TlsTrustedAuthority certSha1Hash(byte[] hash) {
        if(hash == null || hash.length != TlsHashFactory.sha1().length()) {
            throw new IllegalArgumentException("Invalid hash");
        }

        return new CertSha1Hash(hash);
    }

    static Optional<TlsTrustedAuthority> of(ByteBuffer buffer) {
        var id = readBigEndianInt8(buffer);
        return switch (id) {
            case PreAgreed.ID -> Optional.of(PreAgreed.of(buffer));
            case KeySha1Hash.ID -> Optional.of(KeySha1Hash.of(buffer));
            case X509Name.ID -> Optional.of(X509Name.of(buffer));
            case CertSha1Hash.ID -> Optional.of(CertSha1Hash.of(buffer));
            default -> Optional.empty();
        };
    }

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    default int length() {
        return INT8_LENGTH;
    }

    final class PreAgreed implements TlsTrustedAuthority {
        private static final int ID = 0;
        private static final PreAgreed INSTANCE = new PreAgreed();

        public static PreAgreed of(ByteBuffer buffer) {
            if(buffer.hasRemaining()) {
                throw new TlsAlert("Expected pre agreed authority to be empty");
            }

            return INSTANCE;
        }

        private PreAgreed() {

        }

        @Override
        public Byte id() {
            return ID;
        }
    }

    final class KeySha1Hash implements TlsTrustedAuthority {
        private static final int ID = 1;
        private final byte[] hash;
        private KeySha1Hash(byte[] hash) {
            this.hash = hash;
        }

        public static KeySha1Hash of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha1().length());
            return new KeySha1Hash(hash);
        }

        public byte[] hash() {
            return hash;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsTrustedAuthority.super.serialize(buffer);
            writeBytes(buffer, hash);
        }

        @Override
        public int length() {
            return TlsTrustedAuthority.super.length()
                    + hash.length;
        }
    }

    final class X509Name implements TlsTrustedAuthority {
        private static final int ID = 2;
        private final byte[] name;
        private X509Name(byte[] name) {
            this.name = name;
        }

        public static X509Name of(ByteBuffer buffer) {
            var name = readBytesBigEndian16(buffer);
            return new X509Name(name);
        }

        public byte[] name() {
            return name;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsTrustedAuthority.super.serialize(buffer);
            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int length() {
            return TlsTrustedAuthority.super.length()
                    + INT16_LENGTH + name.length;
        }
    }

    final class CertSha1Hash implements TlsTrustedAuthority {
        private static final int ID = 3;
        private final byte[] hash;
        private CertSha1Hash(byte[] hash) {
            this.hash = hash;
        }

        public static CertSha1Hash of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha1().length());
            return new CertSha1Hash(hash);
        }

        public byte[] hash() {
            return hash;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsTrustedAuthority.super.serialize(buffer);
            writeBytes(buffer, hash);
        }

        @Override
        public int length() {
            return TlsTrustedAuthority.super.length()
                    + hash.length;
        }
    }
}
