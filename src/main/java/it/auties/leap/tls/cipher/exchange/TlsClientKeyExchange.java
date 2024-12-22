package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.exception.TlsException;

import java.nio.ByteBuffer;
import java.util.Optional;

public non-sealed interface TlsClientKeyExchange extends TlsKeyExchange {
    static TlsKeyExchange none() {
        return None.INSTANCE;
    }

    static TlsKeyExchange dh(byte[] publicKey) {
        return new DH(publicKey);
    }

    static TlsKeyExchange dhe(byte[] publicKey) {
        return new DHE(publicKey);
    }

    static TlsKeyExchange eccpwd(byte[] password, byte[] publicKey) {
        return new ECCPWD(password, publicKey);
    }

    static TlsKeyExchange ecdh(byte[] publicKey) {
        return new ECDH(publicKey);
    }

    static TlsKeyExchange ecdhe(byte[] publicKey) {
        return new ECDHE(publicKey);
    }

    static TlsKeyExchange gostr256(byte[] publicKey, byte[] additionalData) {
        return new GOSTR(publicKey, additionalData);
    }

    static TlsKeyExchange krb5(byte[] ticket, byte[] additionalData) {
        return new KRB5(ticket, additionalData);
    }

    static TlsKeyExchange psk(byte[] identityKey) {
        return new PSK(identityKey);
    }

    static TlsKeyExchange rsa(byte[] extendedPreMasterSecret) {
        return new RSA(extendedPreMasterSecret);
    }

    static TlsKeyExchange srp(byte[] srpA) {
        return new SRP(srpA);
    }

    byte[] element();
    Optional<byte[]> additionalData();
    
    final class None implements TlsClientKeyExchange {
        private static final None INSTANCE = new None();
        private static final byte[] EMPTY_BUFFER = new byte[0];

        private None() {

        }

        private None(ByteBuffer buffer) {
            if(buffer.hasRemaining()) {
                throw new TlsException("Expected empty payload");
            }
        }

        @Override
        public void serialize(ByteBuffer buffer) {

        }

        @Override
        public int length() {
            return 0;
        }

        @Override
        public byte[] element() {
            return EMPTY_BUFFER;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }
    
    final class DH implements TlsClientKeyExchange {
        private final byte[] publicKey;
        private DH(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        private DH(ByteBuffer buffer) {
            this(readBytesLittleEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }
    
    final class DHE implements TlsClientKeyExchange {
        private final byte[] publicKey;
        private DHE(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        private DHE(ByteBuffer buffer) {
            this.publicKey = readBytesLittleEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class ECCPWD implements TlsClientKeyExchange {
        private final byte[] password;
        private final byte[] publicKey;
        private ECCPWD(byte[] password, byte[] publicKey) {
            this.password = password;
            this.publicKey = publicKey;
        }

        private ECCPWD(ByteBuffer buffer) {
            this.password = readBytesLittleEndian8(buffer);
            this.publicKey = readBytesLittleEndian8(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian8(buffer, password);
            writeBytesLittleEndian8(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT8_LENGTH + password.length
                    + INT8_LENGTH + publicKey.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.of(password);
        }
    }

    final class ECDH implements TlsClientKeyExchange {
        private final byte[] publicKey;
        private ECDH(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        private ECDH(ByteBuffer buffer) {
            this.publicKey = readBytesLittleEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class ECDHE implements TlsClientKeyExchange {
        private final byte[] publicKey;
        private ECDHE(byte[] publicKey) {
            this.publicKey = publicKey;
        }

        private ECDHE(ByteBuffer buffer) {
            this(readBytesLittleEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class GOSTR implements TlsClientKeyExchange {
        private final byte[] publicKey;
        private final byte[] additionalData;
        private GOSTR(byte[] publicKey, byte[] additionalData) {
            this.publicKey = publicKey;
            this.additionalData = additionalData;
        }

        GOSTR(ByteBuffer buffer) {
            this.publicKey = readBytesLittleEndian16(buffer);
            this.additionalData = readBytesLittleEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, publicKey);
            writeBytesLittleEndian16(buffer, additionalData);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length
                    + INT16_LENGTH + additionalData.length;
        }

        @Override
        public byte[] element() {
            return publicKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.of(additionalData);
        }
    }

    final class KRB5 implements TlsClientKeyExchange {
        private final byte[] ticket;
        private final byte[] additionalData;
        private KRB5(byte[] ticket, byte[] additionalData) {
            this.ticket = ticket;
            this.additionalData = additionalData;
        }

        private KRB5(ByteBuffer buffer) {
            this.ticket = readBytesLittleEndian16(buffer);
            this.additionalData = readBytesLittleEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, ticket);
            writeBytesLittleEndian16(buffer, additionalData);
        }

        @Override
        public int length() {
            return INT16_LENGTH + ticket.length
                    + INT16_LENGTH + additionalData.length;
        }

        @Override
        public byte[] element() {
            return ticket;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class PSK implements TlsClientKeyExchange {
        private final byte[] identityKey;
        private PSK(byte[] identityKey) {
            this.identityKey = identityKey;
        }

        private PSK(ByteBuffer buffer) {
            this(readBytesLittleEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, identityKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + identityKey.length;
        }

        @Override
        public byte[] element() {
            return identityKey;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class RSA implements TlsClientKeyExchange {
        private final byte[] extendedPreMasterSecret;
        private RSA(byte[] extendedPreMasterSecret) {
            this.extendedPreMasterSecret = extendedPreMasterSecret;
        }

        private RSA(ByteBuffer buffer) {
            this(readBytesLittleEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, extendedPreMasterSecret);
        }

        @Override
        public int length() {
            return INT16_LENGTH + extendedPreMasterSecret.length;
        }

        @Override
        public byte[] element() {
            return extendedPreMasterSecret;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }

    final class SRP implements TlsClientKeyExchange {
        private final byte[] srpA;
        private SRP(byte[] srpA) {
            this.srpA = srpA;
        }

        private SRP(ByteBuffer buffer) {
            this(readBytesLittleEndian16(buffer));
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesLittleEndian16(buffer, srpA);
        }

        @Override
        public int length() {
            return INT16_LENGTH + srpA.length;
        }

        @Override
        public byte[] element() {
            return srpA;
        }

        @Override
        public Optional<byte[]> additionalData() {
            return Optional.empty();
        }
    }
}
