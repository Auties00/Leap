package it.auties.leap.tls.util;

import it.auties.leap.tls.exception.TlsException;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

// This implementation favors in place transformations when possible
public final class KeyUtils {
    public static DHPublicKey read(byte[] y, BigInteger p, BigInteger g) {
        try {
            var keyFactory = KeyFactory.getInstance("DH");
            var dhPubKeySpecs = new DHPublicKeySpec(
                    fromUnsignedLittleEndianBytes(y),
                    p,
                    g
            );
            return (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
        } catch (NoSuchAlgorithmException exception) {
            throw new TlsException("Missing DH implementation", exception);
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot parse public DH key", exception);
        }
    }

    // Thanks to dave_thompson_085 for answering my question a couple of years ago
    // https://stackoverflow.com/questions/67332030/java-11-curve25519-implementation-doesnt-behave-as-signals-libary
    public static byte[] toUnsignedLittleEndianBytes(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Negative value not supported for unsigned conversion.");
        }

        var bigEndian = value.toByteArray();
        if (bigEndian.length <= 1 || bigEndian[0] != 0) {
            reverse(bigEndian);
            return bigEndian;
        } else {
            var littleEndian = new byte[bigEndian.length - 1];
            for (var i = 0; i < bigEndian.length; i++) {
                littleEndian[i] = bigEndian[bigEndian.length - 1 - i];
            }
            return littleEndian;
        }
    }

    public static BigInteger fromUnsignedLittleEndianBytes(byte[] value) {
        reverse(value);
        return new BigInteger(1, value);
    }

    private static void reverse(byte[] array) {
        for (var i = 0; i < array.length; i++) {
            var temp = array[i];
            array[i] = array[array.length - 1 - i];
            array[array.length - 1 - i] = temp;
        }
    }
}
