package it.auties.leap.tls.encryption;

import it.auties.leap.tls.TlsCipher;
import it.auties.leap.tls.TlsCipher.Type;
import it.auties.leap.tls.TlsHmacType;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.encryption.mode.Cbc;
import it.auties.leap.tls.encryption.mode.Ccm;
import it.auties.leap.tls.encryption.mode.Gcm;
import it.auties.leap.tls.encryption.mode.Null;
import it.auties.leap.tls.engine.TlsEngineMode;
import it.auties.leap.tls.auth.TlsAuthenticator;
import it.auties.leap.tls.key.TlsSessionKeys;
import it.auties.leap.tls.message.TlsMessage.ContentType;

import java.nio.ByteBuffer;

public abstract sealed class TlsEncryption permits Cbc, Ccm, Gcm, Null {
    protected final TlsVersion version;
    protected final Type type;
    protected final TlsAuthenticator authenticator;
    protected final TlsSessionKeys sessionKeys;
    protected final TlsEngineMode mode;
    protected TlsEncryption(TlsVersion version, Type type, TlsAuthenticator authenticator, TlsSessionKeys sessionKeys, TlsEngineMode mode) {
        this.version = version;
        this.type = type;
        this.authenticator = authenticator;
        this.sessionKeys = sessionKeys;
        this.mode = mode;
    }

    protected void addMac(ByteBuffer destination, byte contentId) {
        if(authenticator.hmacType().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var hmac = authenticator.createAuthenticationHmacBlock(contentId, destination, null, false)
                .orElseThrow(() -> new TlsSpecificationException("AesCbc requires an authenticator with mac capabilities"));
        var hmacPosition = destination.limit();
        destination.limit(hmacPosition + hmac.length);
        destination.put(hmacPosition, hmac);
    }

    // Start of taken from sun.security.ssl.SSLCipher
    protected void checkStreamMac(ByteBuffer bb, byte contentType, byte[] sequence) {
        if(authenticator.hmacType().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        var tagLen = authenticator.hmacType()
                .map(TlsHmacType::length)
                .orElse(0);

        // Requires message authentication code for null, stream and
        // block cipher suites.
        if (tagLen != 0) {
            int contentLen = bb.remaining() - tagLen;
            if (contentLen < 0) {
                throw new RuntimeException("bad record");
            }

            // Run MAC computation and comparison on the payload.
            //
            // MAC data would be stripped off during the check.
            if (checkMacTags(contentType, bb, sequence, false)) {
                throw new RuntimeException("bad record MAC");
            }
        }
    }

    protected void checkCBCMac(ByteBuffer bb, byte contentType, byte[] sequence) {
        if(authenticator.hmacType().isEmpty()) {
            authenticator.increaseSequenceNumber();
            return;
        }

        RuntimeException reservedBPE = null;
        var cipheredLength = bb.remaining();
        var tagLen = authenticator.hmacType()
                .map(TlsHmacType::length)
                .orElse(0);
        var pos = bb.position();

        if (tagLen != 0) {
            int contentLen = bb.remaining() - tagLen;
            if (contentLen < 0) {
                reservedBPE = new RuntimeException("bad record");

                // set offset of the dummy MAC
                contentLen = cipheredLength - tagLen;
                bb.limit(pos + cipheredLength);
            }

            // Run MAC computation and comparison on the payload.
            //
            // MAC data would be stripped off during the check.
            if (checkMacTags(contentType, bb, sequence, false)) {
                if (reservedBPE == null) {
                    reservedBPE =
                            new RuntimeException("bad record MAC");
                }
            }

            // Run MAC computation and comparison on the remainder.
            int remainingLen = calculateRemainingLen(cipheredLength, contentLen);

            // NOTE: remainingLen may be bigger (less than 1 block of the
            // hash algorithm of the MAC) than the cipheredLength.
            //
            // Is it possible to use a static buffer, rather than allocate
            // it dynamically?
            remainingLen += authenticator.hmacType()
                    .map(TlsHmacType::length)
                    .orElse(0);
            ByteBuffer temporary = ByteBuffer.allocate(remainingLen);

            // Won't need to worry about the result on the remainder. And
            // then we won't need to worry about what's actual data to
            // check MAC tag on.  We start the check from the header of the
            // buffer so that we don't need to construct a new byte buffer.
            checkMacTags(contentType, temporary, sequence, true);
        }

        // Is it a failover?
        if (reservedBPE != null) {
            throw reservedBPE;
        }
    }

    private boolean checkMacTags(byte contentType, ByteBuffer bb, byte[] sequence, boolean isSimulated) {
        var tagLen = authenticator.hmacType()
                .map(TlsHmacType::length)
                .orElse(0);
        int position = bb.position();
        int lim = bb.limit();
        int macOffset = lim - tagLen;

        bb.limit(macOffset);
        var hash = authenticator.createAuthenticationHmacBlock(contentType, bb, sequence, isSimulated)
                .orElseThrow(() -> new InternalError("Missing mac implementation"));

        bb.position(macOffset);
        bb.limit(lim);
        try {
            int[] results = compareMacTags(bb, hash);
            return (results[0] != 0);
        } finally {
            // reset to the data
            bb.position(position);
            bb.limit(macOffset);
        }
    }

    private static int[] compareMacTags(ByteBuffer bb, byte[] tag) {
        // An array of hits is used to prevent Hotspot optimization for
        // the purpose of a constant-time check.
        int[] results = {0, 0};     // {missed #, matched #}

        // The caller ensures there are enough bytes available in the buffer.
        // So we won't need to check the remaining of the buffer.
        for (byte t : tag) {
            if (bb.get() != t) {
                results[0]++;       // mismatched bytes
            } else {
                results[1]++;       // matched bytes
            }
        }

        return results;
    }

    private int calculateRemainingLen(int fullLen, int usedLen) {
        int blockLen = authenticator.hmacType()
                .map(macType -> macType.toHash().blockLength())
                .orElse(0);
        int minimalPaddingLen = authenticator.hmacType()
                .map(TlsHmacType::minimalPaddingLength)
                .orElse(0);

        // (blockLen - minimalPaddingLen) is the maximum message size of
        // the last block of hash function operation. See FIPS 180-4, or
        // MD5 specification.
        fullLen += 13 - (blockLen - minimalPaddingLen);
        usedLen += 13 - (blockLen - minimalPaddingLen);

        // Note: fullLen is always not less than usedLen, and blockLen
        // is always bigger than minimalPaddingLen, so we don't worry
        // about negative values. 0x01 is added to the result to ensure
        // that the return value is positive.  The extra one byte does
        // not impact the overall MAC compression function evaluations.
        return 0x01 + (int)(Math.ceil(fullLen/(1.0d * blockLen)) -
                Math.ceil(usedLen/(1.0d * blockLen))) * blockLen;
    }

    // End of taken from sun.security.ssl.SSLCipher

    public abstract void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output);
    public abstract void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output, byte[] sequence);
    public abstract int nonceLength();

    public static TlsEncryption of(
            TlsVersion version,
            TlsCipher cipher,
            TlsAuthenticator authenticator,
            TlsSessionKeys sessionKeys,
            TlsEngineMode mode
    ) {
        return switch (cipher.encryption()) {
            case NULL -> new Null(authenticator);
            case AES_128_GCM, AES_256_GCM -> new Gcm(version, cipher.encryption(), authenticator, sessionKeys, mode);
            case AES_128_CBC, AES_256_CBC -> new Cbc(version, cipher.encryption(), authenticator, sessionKeys, mode);

            case AES_128_CCM, AES_128_CCM_8, AES_256_CCM, AES_256_CCM_8 -> new Ccm(version, cipher.encryption(), authenticator, sessionKeys, mode);

            case ARIA_128_CBC, ARIA_256_CBC -> null;
            case ARIA_128_GCM, ARIA_256_GCM -> null;

            case CAMELLIA_128_CBC, CAMELLIA_256_CBC -> null;
            case CAMELLIA_128_GCM, CAMELLIA_256_GCM -> null;

            case CHACHA20_POLY1305 -> null;

            case DES40_CBC -> null;
            case DES_CBC -> null;
            case DES_CBC_40 -> null;
            case IDEA_CBC -> null;
            case KUZNYECHIK_CTR -> null;
            case KUZNYECHIK_MGM_L -> null;
            case KUZNYECHIK_MGM_S -> null;
            case MAGMA_CTR -> null;
            case MAGMA_MGM_L -> null;
            case MAGMA_MGM_S -> null;
            case RC2_CBC_40 -> null;
            case RC4_128 -> null;
            case RC4_40 -> null;
            case SEED_CBC -> null;
            case SM4_CCM -> null;
            case SM4_GCM -> null;
            case GOST_28147_CNT -> null;
            case TRIPLE_DES_EDE_CBC -> null;
        };
    }
}
