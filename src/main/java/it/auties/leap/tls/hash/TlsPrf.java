package it.auties.leap.tls.hash;

import java.util.Arrays;

// Adapted from JDK com.sun.crypto.provider.PrfGenerator
public final class TlsPrf {
    private static final byte[] EMPTY_BUFFER = new byte[0];
    private static final byte[] HMAC_IPAD_64 = genPad((byte) 0x36, 64);
    private static final byte[] HMAC_IPAD_128 = genPad((byte) 0x36, 128);
    private static final byte[] HMAC_OPAD_64 = genPad((byte) 0x5c, 64);
    private static final byte[] HMAC_OPAD_128 = genPad((byte) 0x5c, 128);

    private static byte[] genPad(byte b, int count) {
        var padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    public static byte[] seed(byte[] clientRandom, byte[] serverRandom) {
        var seed = new byte[clientRandom.length + serverRandom.length];
        System.arraycopy(clientRandom, 0, seed, 0, clientRandom.length);
        System.arraycopy(serverRandom, 0, seed, clientRandom.length, serverRandom.length);
        return seed;
    }

    public static byte[] tls12Prf(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength, TlsHash hash) {
        var mdPRFLen = hash.length();
        var mdPRFBlockSize = hash.blockLength();

        if (secret == null) {
            secret = EMPTY_BUFFER;
        }

        if (secret.length > mdPRFBlockSize) {
            hash.update(secret);
            secret = hash.digest(true);
        }

        var output = new byte[outputLength];
        expand(hash, mdPRFLen, secret, 0, secret.length, labelBytes, seed, output, getIpad(mdPRFBlockSize), getOpad(mdPRFBlockSize));
        return output;
    }

    private static byte[] getOpad(int mdPRFBlockSize) {
        return switch (mdPRFBlockSize) {
            case 64 -> HMAC_OPAD_64.clone();
            case 128 -> HMAC_OPAD_128.clone();
            default -> throw new RuntimeException("Unexpected block size.");
        };
    }

    private static byte[] getIpad(int mdPRFBlockSize) {
        return switch (mdPRFBlockSize) {
            case 64 -> HMAC_IPAD_64.clone();
            case 128 -> HMAC_IPAD_128.clone();
            default -> throw new RuntimeException("Unexpected block size.");
        };
    }

    public static byte[] tls10Prf(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength) {
        return tls10Prf(secret, labelBytes, seed, outputLength, TlsHash.md5(), TlsHash.sha1());
    }

    public static byte[] tls10Prf(byte[] secret, byte[] labelBytes, byte[] seed, int outputLength, TlsHash md5, TlsHash sha) {
        if (secret == null) {
            secret = EMPTY_BUFFER;
        }

        var off = secret.length >> 1;
        var seclen = off + (secret.length & 1);

        var secKey = secret;
        var keyLen = seclen;
        var output = new byte[outputLength];

        if (seclen > 64) {
            md5.update(secret, 0, seclen);
            secKey = md5.digest(true);
            md5.reset();
            keyLen = secKey.length;
        }
        expand(md5, 16, secKey, 0, keyLen, labelBytes, seed, output, HMAC_IPAD_64, HMAC_OPAD_64);

        if (seclen > 64) {
            sha.update(secret, off, seclen);
            secKey = sha.digest(true);
            sha.reset();
            keyLen = secKey.length;
            off = 0;
        }
        expand(sha, 20, secKey, off, keyLen, labelBytes, seed, output, HMAC_IPAD_64, HMAC_OPAD_64);

        return output;
    }

    private static void expand(TlsHash digest, int hmacSize, byte[] secret, int secOff, int secLen, byte[] label, byte[] seed, byte[] output, byte[] pad1, byte[] pad2) {
        for (var i = 0; i < secLen; i++) {
            pad1[i] ^= secret[i + secOff];
            pad2[i] ^= secret[i + secOff];
        }

        var tmp = new byte[hmacSize];
        byte[] aBytes = null;

        var remaining = output.length;
        var ofs = 0;
        while (remaining > 0) {
            digest.update(pad1);
            if (aBytes == null) {
                digest.update(label);
                digest.update(seed);
            } else {
                digest.update(aBytes);
            }
            digest.digest(tmp, 0, hmacSize, true);

            digest.update(pad2);
            digest.update(tmp);
            if (aBytes == null) {
                aBytes = new byte[hmacSize];
            }
            digest.digest(aBytes, 0, hmacSize, true);

            digest.update(pad1);
            digest.update(aBytes);
            digest.update(label);
            digest.update(seed);
            digest.digest(tmp, 0, hmacSize, true);


            digest.update(pad2);
            digest.update(tmp);
            digest.digest(tmp, 0, hmacSize, true);

            digest.reset();

            var k = Math.min(hmacSize, remaining);
            for (var i = 0; i < k; i++) {
                output[ofs++] ^= tmp[i];
            }
            remaining -= k;
        }

        Arrays.fill(tmp, (byte)0);
    }
}
