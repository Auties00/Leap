package it.auties.leap.tls.cipher.exchange;

import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

// TODO: Handle this in a better way
public abstract sealed class TlsExchangeMac {
    private static final int BLOCK_LENGTH = 8;
    private static final byte[] EMPTY_BUFFER = new byte[0];

    public static TlsExchangeMac of(TlsVersion version, TlsHashFactory hashFactory, byte[] macKey) {
        return switch (version) {
            case TLS13 -> new TLS13();
            case TLS12, TLS11, TLS10 -> new TLS10(version, hashFactory == null ? null : TlsHmac.of(hashFactory.newHash()), macKey);
            case SSL30 -> new SSL30(hashFactory == null ? null : TlsHmac.of(hashFactory.newHash()), macKey);
            case DTLS13 -> new DTLS13();
            case DTLS12, DTLS10 -> new DTLS10(version, hashFactory == null ? null : TlsHmac.of(hashFactory.newHash()), macKey);
        };
    }

    final TlsVersion version;
    final byte[] block;
    final boolean dtls;
    final TlsHmac mac;
    private TlsExchangeMac(TlsVersion version, TlsHmac hmac, byte[] hmacKey, byte[] block, boolean dtls) {
        this.version = version;
        this.block = block;
        this.dtls = dtls;
        if(hmac != null) {
            this.mac = hmac;
            mac.init(hmacKey);
        }else {
            this.mac = null;
        }
    }

    public TlsVersion version() {
        return version;
    }

    public abstract byte[] createAuthenticationBlock(byte type, int length, byte[] sequence);

    public Optional<byte[]> createAuthenticationHmacBlock(byte type, ByteBuffer buffer, byte[] sequence, boolean isSimulated) {
        if(mac == null) {
            return Optional.empty();
        }

        if (mac.blockLength() == 0) {
            return Optional.of(EMPTY_BUFFER);
        }

        if (!isSimulated) {
            var additional = createAuthenticationBlock(type, buffer.remaining(), sequence);
            mac.update(additional);
        }

        var position = buffer.position();
        mac.update(buffer);
        buffer.position(position);
        return Optional.of(mac.doFinal());
    }

    public final Optional<TlsHmac> hmac() {
        return Optional.ofNullable(mac);
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

    private static final class SSL30 extends TlsExchangeMac {
        private static final int BLOCK_SIZE = 11;

        private SSL30(TlsHmac hmac, byte[] hmacKey) {
            super(TlsVersion.SSL30, hmac, hmacKey, new byte[BLOCK_SIZE], false);
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

    private static final class TLS10 extends TlsExchangeMac {
        private static final int BLOCK_SIZE = 13;

        private TLS10(TlsVersion version, TlsHmac hmac, byte[] hmacKey) {
            super(version, hmac, hmacKey, new byte[BLOCK_SIZE], false);
            block[9] = version.id().major();
            block[10] = version.id().minor();
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

    private static final class TLS13 extends TlsExchangeMac {
        private static final int BLOCK_SIZE = 13;

        private TLS13() {
            super(TlsVersion.TLS13, null, null, new byte[BLOCK_SIZE], false);
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

    private static final class DTLS10 extends TlsExchangeMac {
        private static final int BLOCK_SIZE = 13;

        private DTLS10(TlsVersion version, TlsHmac hmac, byte[] hmacKey) {
            super(version, hmac, hmacKey, new byte[BLOCK_SIZE], true);
            block[9] = version.id().major();
            block[10] = version.id().minor();
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

    private static final class DTLS13 extends TlsExchangeMac {
        private static final int BLOCK_SIZE = 13;

        private DTLS13() {
            super(TlsVersion.DTLS13, null, null, new byte[BLOCK_SIZE], true);
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