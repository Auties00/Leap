package it.auties.leap.tls.hash;

import java.util.Arrays;
import java.util.Objects;

public final class TlsHkdf {
    public static TlsHkdf of(TlsHmac hmac) {
        return new TlsHkdf(hmac);
    }

    private final TlsHmac hmac;
    private TlsHkdf(TlsHmac hmac) {
        this.hmac = hmac;
    }

    public byte[] extract(byte[] salt, byte[] inputKey) {
        if (salt == null) {
            salt = new byte[hmac.length()];
        }

        hmac.init(salt);
        hmac.update(inputKey);
        return hmac.doFinal();
    }

    public byte[] expand(byte[] key, byte[] info, int outLen) {
        // Calculate the number of rounds of HMAC that are needed to
        // meet the requested data.  Then set up the buffers we will need.
        Objects.requireNonNull(key, "A null PRK is not allowed.");

        // Output from the expand operation must be <= 255 * hmac length
        if (outLen > 255 * hmac.length()) {
            throw new IllegalArgumentException("Requested output length " +
                    "exceeds maximum length allowed for HKDF expansion");
        }

        hmac.init(key);
        if (info == null) {
            info = new byte[0];
        }
        var rounds = (outLen + hmac.length() - 1) / hmac.length();
        var kdfOutput = new byte[rounds * hmac.length()];
        var offset = 0;
        var tLength = 0;

        for (int i = 0; i < rounds ; i++) {

            // Calculate this round
            // Add T(i).  This will be an empty string on the first
            // iteration since tLength starts at zero.  After the first
            // iteration, tLength is changed to the HMAC length for the
            // rest of the loop.
            hmac.update(kdfOutput,
                    Math.max(0, offset - hmac.length()), tLength);
            hmac.update(info);                       // Add info
            hmac.update((byte)(i + 1));              // Add round number
            hmac.doFinal(kdfOutput, offset);

            tLength = hmac.length();
            offset += hmac.length();
        }

        return Arrays.copyOfRange(kdfOutput, 0, outLen);
    }
}

