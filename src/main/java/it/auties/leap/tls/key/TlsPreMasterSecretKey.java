package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsCipher;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.TlsRecord.*;

public interface TlsPreMasterSecretKey {
    void serialize(ByteBuffer buffer);

    int length();

    static TlsPreMasterSecretKey of(TlsCipher cipher, ByteBuffer buffer) {
        return switch (cipher.keyExchange()) {
            case DH -> {
                var Yc = readBytes16(buffer);
                yield new DH(Yc);
            }
            case DHE -> {
                var Yc = readBytes16(buffer);
                yield new DHE(Yc);
            }
            case ECCPWD -> {
                var scalar = readBytes8(buffer);
                var element = readBytes8(buffer);
                yield new ECCPWD(scalar, element);
            }
            case ECDH -> {
                var point = readBytes8(buffer);
                yield new ECDH(point);
            }
            case ECDHE -> {
                var point = readBytes8(buffer);
                yield new ECDHE(point);
            }
            case GOSTR341112_256 -> {
                var encryptedKey = readBytes16(buffer);
                var additionalData = readBytes16(buffer);
                yield new GOSTR(encryptedKey, additionalData);
            }
            case KRB5 -> {
                var ticket = readBytes16(buffer);
                var authData = readBytes16(buffer);
                yield new KRB5(ticket, authData);
            }
            case NULL -> new NULL();
            case PSK -> {
                var pskIdentity = readBytes16(buffer);
                yield new PSK(pskIdentity);
            }
            case RSA -> {
                var extendedPreMasterSecret = readBytes16(buffer);
                yield new RSA(extendedPreMasterSecret);
            }
            case SRP -> {
                var srpA = readBytes16(buffer);
                yield new SRP(srpA);
            }
        };
    }

    record DH(byte[] Yc) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, Yc);
        }

        @Override
        public int length() {
            return INT16_LENGTH + Yc.length;
        }
    }

    record DHE(byte[] Yc) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, Yc);
        }

        @Override
        public int length() {
            return INT16_LENGTH + Yc.length;
        }
    }

    record ECCPWD(byte[] scalar, byte[] element) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes8(buffer, scalar);
            writeBytes8(buffer, element);
        }

        @Override
        public int length() {
            return INT8_LENGTH + scalar.length
                    + INT8_LENGTH + element.length;
        }
    }

    record ECDH(byte[] point) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes8(buffer, point);
        }

        @Override
        public int length() {
            return INT8_LENGTH + point.length;
        }
    }

    record ECDHE(byte[] point) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes8(buffer, point);
        }

        @Override
        public int length() {
            return INT8_LENGTH + point.length;
        }
    }

    record GOSTR(byte[] encryptedKey, byte[] additionalData) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, encryptedKey);
            writeBytes16(buffer, additionalData);
        }

        @Override
        public int length() {
            return INT16_LENGTH + encryptedKey.length
                    + INT16_LENGTH + additionalData.length;
        }
    }

    record KRB5(byte[] ticket, byte[] authData) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, ticket);
            writeBytes16(buffer, authData);
        }

        @Override
        public int length() {
            return INT16_LENGTH + ticket.length
                    + INT16_LENGTH + authData.length;
        }
    }

    record NULL() implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {

        }

        @Override
        public int length() {
            return 0;
        }
    }

    record PSK(byte[] pskIdentity) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, pskIdentity);
        }

        @Override
        public int length() {
            return INT16_LENGTH + pskIdentity.length;
        }
    }

    record RSA(byte[] extendedPreMasterSecret) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, extendedPreMasterSecret);
        }

        @Override
        public int length() {
            return INT16_LENGTH + extendedPreMasterSecret.length;
        }
    }

    record SRP(byte[] srpA) implements TlsPreMasterSecretKey {
        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytes16(buffer, srpA);
        }

        @Override
        public int length() {
            return INT16_LENGTH + srpA.length;
        }
    }
}
