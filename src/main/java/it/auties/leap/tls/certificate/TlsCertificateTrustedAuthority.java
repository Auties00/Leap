package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsCertificateTrustedAuthority extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static TlsCertificateTrustedAuthority preAgreed() {
        return PreAgreed.INSTANCE;
    }

    static TlsCertificateTrustedAuthority keySha1Hash(byte[] hash) {
        if (hash == null) {
            throw new TlsAlert("Key sha1 hash cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var expectedHashLength = TlsHashFactory.sha1().length();
        if(hash.length != expectedHashLength) {
            throw new TlsAlert("Key sha1 hash length mismatch: expected %s, got %s".formatted(expectedHashLength, hash.length), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new KeySha1Hash(hash);
    }

    static TlsCertificateTrustedAuthority x509Name(byte[] name) {
        if (name == null) {
            throw new TlsAlert("Name cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new X509Name(name);
    }

    static TlsCertificateTrustedAuthority certSha1Hash(byte[] hash) {
        if (hash == null) {
            throw new TlsAlert("Cert sha1 hash cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var expectedHashLength = TlsHashFactory.sha1().length();
        if(hash.length != expectedHashLength) {
            throw new TlsAlert("Cert sha1 hash length mismatch: expected %s, got %s".formatted(expectedHashLength, hash.length), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new CertSha1Hash(hash);
    }

    Type type();
    TlsCertificateTrustedAuthority deserialize(ByteBuffer buffer);

    final class PreAgreed implements TlsCertificateTrustedAuthority {
        private static final PreAgreed INSTANCE = new PreAgreed();

        @Override
        public TlsCertificateTrustedAuthority deserialize(ByteBuffer buffer) {
            buffer.position(buffer.limit());
            return INSTANCE;
        }

        private PreAgreed() {

        }

        @Override
        public Byte id() {
            return 0;
        }

        @Override
        public Type type() {
            return Type.PRE_AGREED;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
        }

        @Override
        public int length() {
            return INT8_LENGTH;
        }
    }

    final class KeySha1Hash implements TlsCertificateTrustedAuthority {
        private final byte[] hash;
        private KeySha1Hash(byte[] hash) {
            this.hash = hash;
        }

        @Override
        public TlsCertificateTrustedAuthority deserialize(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha1().length());
            return new KeySha1Hash(hash);
        }

        public byte[] hash() {
            return hash;
        }

        @Override
        public Type type() {
            return Type.KEY_SHA1_HASH;
        }

        @Override
        public Byte id() {
            return 1;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytes(buffer, hash);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + hash.length;
        }
    }

    final class X509Name implements TlsCertificateTrustedAuthority {
        private final byte[] name;
        private X509Name(byte[] name) {
            this.name = name;
        }

        @Override
        public TlsCertificateTrustedAuthority deserialize(ByteBuffer buffer) {
            var name = readBytesBigEndian16(buffer);
            return new X509Name(name);
        }

        public byte[] name() {
            return name;
        }

        @Override
        public Type type() {
            return Type.X509_NAME;
        }

        @Override
        public Byte id() {
            return 2;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytesBigEndian16(buffer, name);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + INT16_LENGTH + name.length;
        }
    }

    final class CertSha1Hash implements TlsCertificateTrustedAuthority {
        private final byte[] hash;
        private CertSha1Hash(byte[] hash) {
            this.hash = hash;
        }

        @Override
        public TlsCertificateTrustedAuthority deserialize(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha1().length());
            return new CertSha1Hash(hash);
        }

        public byte[] hash() {
            return hash;
        }

        @Override
        public Type type() {
            return Type.CERT_SHA1_HASH;
        }

        @Override
        public Byte id() {
            return 3;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytes(buffer, hash);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + hash.length;
        }
    }

    enum Type {
        PRE_AGREED,
        KEY_SHA1_HASH,
        X509_NAME,
        CERT_SHA1_HASH
    }
}
