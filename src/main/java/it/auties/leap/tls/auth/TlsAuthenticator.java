package it.auties.leap.tls.auth;

import it.auties.leap.tls.TlsHmacType;
import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.hash.TlsHmac;

import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;
import java.util.Optional;

public abstract sealed class TlsAuthenticator {
    private static final int BLOCK_LENGTH = 8;
    private static final byte[] EMPTY_BUFFER = new byte[0];

    public static TlsAuthenticator of(TlsVersion version, TlsCipher cipher, Key key) {
        if (cipher.encryption().mode().category() == TlsCipher.Type.Mode.Category.AEAD) {
            return switch (version) {
                case TLS13 -> new TLS13Authenticator();
                case TLS12, TLS11, TLS10 -> new TLS10Authenticator(version, null, null);
                case SSL30 -> new SSL30Authenticator(null, null);
                case DTLS13 -> new DTLS13Authenticator();
                case DTLS12, DTLS10 -> new DTLS10Authenticator(version, null, null);
            };
        } else {
            return switch (version) {
                case TLS13 -> throw new TlsSpecificationException("No MacAlg used in TLS 1.3");
                case TLS12, TLS11, TLS10 -> new TLS10Authenticator(version, cipher.hmac(), key);
                case SSL30 -> new SSL30Authenticator(cipher.hmac(), key);
                case DTLS13 -> throw new TlsSpecificationException("No MacAlg used in DTLS 1.3");
                case DTLS12, DTLS10 -> new DTLS10Authenticator(version, cipher.hmac(), key);
            };
        }
    }

    final byte[] block;
    final boolean dtls;
    final TlsHmac mac;
    private TlsAuthenticator(TlsHmacType tlsHmacType, Key hmacKey, byte[] block, boolean dtls) {
        this.block = block;
        this.dtls = dtls;
        if(tlsHmacType != null) {
            this.mac = TlsHmac.of(tlsHmacType);
            mac.init(hmacKey);
        }else {
            this.mac = null;
        }
    }

    public abstract byte[] createAuthenticationBlock(byte type, int length, byte[] sequence);

    public Optional<byte[]> createAuthenticationHmacBlock(byte type, ByteBuffer buffer, byte[] sequence, boolean isSimulated) {
        var hashType = hmacType()
                .orElse(null);
        if(hashType == null) {
            return Optional.empty();
        }

        if (hashType == TlsHmacType.NULL) {
            return Optional.of(EMPTY_BUFFER);
        }

        if (!isSimulated) {
            var additional = createAuthenticationBlock(type, buffer.remaining(), sequence);
            mac.update(additional);
        }

        mac.update(buffer);
        return Optional.of(mac.doFinal());
    }

    public final Optional<TlsHmacType> hmacType() {
        return mac != null ? Optional.ofNullable(mac.type()) : Optional.empty();
    }

    // Approach copied from JDK internals
    // I implemented this just because it's a possible edge case
    // But one would need to send/receive billions of messages
    public final boolean isOverflow() {
        return (block.length != 0 &&
                (dtls || block[0] == (byte) 0xFF) && (dtls || block[1] == (byte) 0xFF) &&
                block[2] == (byte) 0xFF && block[3] == (byte) 0xFF &&
                block[4] == (byte) 0xFF && block[5] == (byte) 0xFF &&
                block[6] == (byte) 0xFF);
    }

    public final void setEpochNumber(int epoch) {
        if(dtls) {
            block[0] = (byte) ((epoch >> 8) & 0xFF);
            block[1] = (byte) (epoch & 0xFF);
        }
    }

    public final byte[] sequenceNumber() {
        return Arrays.copyOf(block, BLOCK_LENGTH);
    }

    public final void increaseSequenceNumber() {
        if(isOverflow()) {
            throw new IllegalStateException("Overflow");
        }

        var k = 7;
        while ((k >= 0) && (++block[k] == 0)) {
            k--;
        }
    }

    private static final class SSL30Authenticator extends TlsAuthenticator {
        private static final int BLOCK_SIZE = 11;

        private SSL30Authenticator(TlsHmacType tlsHmacType, Key hmacKey) {
            super(tlsHmacType, hmacKey, new byte[BLOCK_SIZE], false);
        }

        @Override
        public byte[] createAuthenticationBlock(byte type, int length, byte[] sequence) {
            var ad = block.clone();

            increaseSequenceNumber();

            ad[8] = type;
            ad[9] = (byte) (length >> 8);
            ad[10] = (byte) (length);

            return ad;
        }
    }

    private static final class TLS10Authenticator extends TlsAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private TLS10Authenticator(TlsVersion protocolVersion, TlsHmacType tlsHmacType, Key hmacKey) {
            super(tlsHmacType, hmacKey, new byte[BLOCK_SIZE], false);
            block[9] = protocolVersion.id().major();
            block[10] = protocolVersion.id().minor();
        }

        @Override
        public byte[] createAuthenticationBlock(byte type, int length, byte[] sequence) {
            var ad = block.clone();
            if (sequence != null) {
                if (sequence.length != BLOCK_LENGTH) {
                    throw new RuntimeException("Insufficient explicit sequence number bytes");
                }

                System.arraycopy(sequence, 0, ad, 0, sequence.length);
            } else {
                increaseSequenceNumber();
            }

            ad[8] = type;
            ad[11] = (byte) (length >> 8);
            ad[12] = (byte) (length);

            return ad;
        }
    }

    private static final class TLS13Authenticator extends TlsAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private TLS13Authenticator() {
            super(null, null, new byte[BLOCK_SIZE], false);
            block[9] = TlsVersion.TLS12.id().major();
            block[10] = TlsVersion.TLS12.id().minor();
        }

        @Override
        public byte[] createAuthenticationBlock(byte type, int length, byte[] sequence) {
            var ad = Arrays.copyOfRange(block, 8, 13);

            increaseSequenceNumber();

            ad[0] = type;
            ad[3] = (byte) (length >> 8);
            ad[4] = (byte) (length & 0xFF);

            return ad;
        }
    }

    private static final class DTLS10Authenticator extends TlsAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private DTLS10Authenticator(TlsVersion protocolVersion, TlsHmacType tlsHmacType, Key hmacKey) {
            super(tlsHmacType, hmacKey, new byte[BLOCK_SIZE], true);
            block[9] = protocolVersion.id().major();
            block[10] = protocolVersion.id().minor();
        }

        @Override
        public byte[] createAuthenticationBlock(byte type, int length, byte[] sequence) {
            var ad = block.clone();
            if (sequence != null) {
                if (sequence.length != 8) {
                    throw new RuntimeException(
                            "Insufficient explicit sequence number bytes");
                }

                System.arraycopy(sequence, 0, ad, 0, sequence.length);
            } else {
                increaseSequenceNumber();
            }

            ad[8] = type;
            ad[11] = (byte) (length >> 8);
            ad[12] = (byte) (length);

            return ad;
        }
    }

    private static final class DTLS13Authenticator extends TlsAuthenticator {
        private static final int BLOCK_SIZE = 13;

        private DTLS13Authenticator() {
            super(null, null, new byte[BLOCK_SIZE], true);
            block[9] = TlsVersion.TLS12.id().major();
            block[10] = TlsVersion.TLS12.id().minor();
        }

        @Override
        public byte[] createAuthenticationBlock(byte type, int length, byte[] sequence) {
            var ad = Arrays.copyOfRange(block, 8, 13);

            increaseSequenceNumber();

            ad[0] = type;
            ad[3] = (byte) (length >> 8);
            ad[4] = (byte) (length & 0xFF);

            return ad;
        }
    }
}