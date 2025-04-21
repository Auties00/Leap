package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsAuthorizationHash extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static Optional<TlsAuthorizationHash> of(ByteBuffer buffer) {
        var id = readBigEndianInt8(buffer);
        return switch (id) {
            case None.ID -> Optional.of(None.of(buffer));
            case MD5.ID -> Optional.of(MD5.of(buffer));
            case SHA1.ID -> Optional.of(SHA1.of(buffer));
            case SHA224.ID -> Optional.of(SHA224.of(buffer));
            case SHA256.ID -> Optional.of(SHA256.of(buffer));
            case SHA384.ID -> Optional.of(SHA384.of(buffer));
            case SHA512.ID -> Optional.of(SHA512.of(buffer));
            default -> Optional.empty();
        };
    }

    static None none() {
        return None.INSTANCE;
    }

    static MD5 md5(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.md5().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new MD5(hash);
    }

    static SHA1 sha1(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.sha1().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SHA1(hash);
    }

    static SHA224 sha224(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.sha224().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SHA224(hash);
    }

    static SHA256 sha256(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.sha256().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SHA256(hash);
    }

    static SHA384 sha384(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.sha384().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SHA384(hash);
    }

    static SHA512 sha512(byte[] hash) {
        if(hash == null || hash.length == TlsHashFactory.sha512().length()) {
            throw new TlsAlert("Invalid hash", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SHA512(hash);
    }

    Optional<byte[]> data();

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    default int length() {
        return INT8_LENGTH;
    }

    final class None implements TlsAuthorizationHash {
        private static final int ID = 0;

        private static final None INSTANCE = new None();

        private None() {

        }

        public static None of(ByteBuffer buffer) {
            if (buffer.hasRemaining()) {
                throw new TlsAlert("Expected empty payload", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            return INSTANCE;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.empty();
        }
    }

    final class MD5 implements TlsAuthorizationHash {
        private static final int ID = 1;

        private final byte[] hash;

        private MD5(byte[] hash) {
            this.hash = hash;
        }

        public static MD5 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.md5().length());
            return new MD5(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }

    final class SHA1 implements TlsAuthorizationHash {
        private static final int ID = 2;

        private final byte[] hash;

        private SHA1(byte[] hash) {
            this.hash = hash;
        }

        public static SHA1 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha1().length());
            return new SHA1(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }

    final class SHA224 implements TlsAuthorizationHash {
        private static final int ID = 3;

        private final byte[] hash;

        private SHA224(byte[] hash) {
            this.hash = hash;
        }

        public static SHA224 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHashFactory.sha224().length());
            return new SHA224(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }

    final class SHA256 implements TlsAuthorizationHash {
        private static final int ID = 4;

        private final byte[] hash;

        private SHA256(byte[] hash) {
            this.hash = hash;
        }

        public static SHA256 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha256().length());
            return new SHA256(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }

    final class SHA384 implements TlsAuthorizationHash {
        private static final int ID = 5;

        private final byte[] hash;

        private SHA384(byte[] hash) {
            this.hash = hash;
        }

        public static SHA384 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHash.sha384().length());
            return new SHA384(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }

    final class SHA512 implements TlsAuthorizationHash {
        private static final int ID = 6;

        private final byte[] hash;

        private SHA512(byte[] hash) {
            this.hash = hash;
        }

        public static SHA256 of(ByteBuffer buffer) {
            var hash = readBytes(buffer, TlsHashFactory.sha512().length());
            return new SHA256(hash);
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public Optional<byte[]> data() {
            return Optional.of(hash);
        }
    }
}
