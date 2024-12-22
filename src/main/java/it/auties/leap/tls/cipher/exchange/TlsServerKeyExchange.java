package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.exception.TlsException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.util.Optional;

public non-sealed interface TlsServerKeyExchange extends TlsKeyExchange {
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
    byte[] generatePreMasterSecret(TlsClientKeyExchange clientKeyExchange);
    
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
        private static final int COMPONENT_LENGTH = 32;

        private final DHPublicKey publicKey;
        private DHE(DHPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        private DHE(ByteBuffer buffer) {
            try {
                var keyFactory = KeyFactory.getInstance("DH");
                var p = readBytesLittleEndian16(buffer);
                var g = readBytesLittleEndian16(buffer);
                var y = readBytesLittleEndian16(buffer);
                var dhPubKeySpecs = new DHPublicKeySpec(
                        convertKeyToJca(y),
                        convertKeyToJca(p),
                        convertKeyToJca(g)
                );
                this.publicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs)
            }catch (GeneralSecurityException exception) {
                throw new TlsException("Cannot read DHE server key", exception);
            }
        }


        @Override
        public void serialize(ByteBuffer buffer) {
            var dhPublicKey = publicKey;
            var p = convertJcaToKey(dhPublicKey.getParams().getP());
            var g = convertJcaToKey(dhPublicKey.getParams().getP());
            var y = convertJcaToKey(dhPublicKey.getParams().getP());
            writeBytesLittleEndian16(buffer, p);
            writeBytesLittleEndian16(buffer, g);
            writeBytesLittleEndian16(buffer, y);
        }

        @Override
        public int length() {
            return INT16_LENGTH + COMPONENT_LENGTH
                    + INT16_LENGTH + COMPONENT_LENGTH
                    + INT16_LENGTH + COMPONENT_LENGTH;
        }

        @Override
        public byte[] generatePreMasterSecret(TlsClientKeyExchange clientKeyExchange) {
            if(!(clientKeyExchange instanceof TlsClientKeyExchange.DH dhClientKeyExchange)) {
                throw new TlsException("Key share mismatch");
            }

            try {
                var keyAgreement = KeyAgreement.getInstance("DH");
                keyAgreement.init(dhClientKeyExchange.jceKeyPair().getPrivate());
                keyAgreement.doPhase(remote.jcaPublicKey(), true);
                return keyAgreement.generateSecret();
            }catch (GeneralSecurityException exception) {
                throw new TlsException("Cannot generate pre master secret", exception);
            }
        }

        private static BigInteger convertKeyToJca(byte[] arr) {
            var result = new byte[32];
            var padding = result.length - arr.length;
            for(var i = 0; i < arr.length; i++) {
                result[i + padding] = arr[arr.length - (i + 1)];
            }

            return new BigInteger(result);
        }

        private static byte[] convertJcaToKey(BigInteger bigInteger) {
            var arr = bigInteger.toByteArray();
            var result = new byte[32];
            var padding = result.length - arr.length;
            for(var i = 0; i < arr.length; i++) {
                result[i + padding] = arr[arr.length - (i + 1)];
            }

            return result;
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

    final class SRP implements TlsServerKeyExchange {
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
