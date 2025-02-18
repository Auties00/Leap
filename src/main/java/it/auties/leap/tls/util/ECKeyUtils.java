package it.auties.leap.tls.util;

import java.math.BigInteger;

// Thanks to dave_thompson_085 for answering my question a couple of years ago
// https://stackoverflow.com/questions/67332030/java-11-curve25519-implementation-doesnt-behave-as-signals-libary
public final class ECKeyUtils {
    public static byte[] toUnsignedLittleEndianBytes(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Negative value not supported for unsigned conversion.");
        }

        var bigEndian = value.toByteArray();
        if (bigEndian.length <= 1 || bigEndian[0] != 0) {
            var middle = bigEndian.length >>> 1;
            for (var i = 0; i < middle; i++) {
                var temp = bigEndian[i];
                bigEndian[i] = bigEndian[bigEndian.length - 1 - i];
                bigEndian[bigEndian.length - 1 - i] = temp;
            }
            return bigEndian;
        } else {
            var littleEndian = new byte[bigEndian.length - 1];
            for (var i = 0; i < littleEndian.length; i++) {
                littleEndian[i] = bigEndian[bigEndian.length - 1 - i];
            }
            return littleEndian;
        }
    }

    public static BigInteger fromUnsignedLittleEndianBytes(byte[] value) {
        var result = new byte[value.length];
        for (var i = 0; i < result.length; i++) {
            result[i] = value[value.length - 1 - i];
        }
        return new BigInteger(1, result);
    }
}
