package it.auties.leap.tls.util;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class TlsKeyUtils {
    public static final byte[] LABEL_KEY_EXPANSION = {107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110};
    public static final byte[] LABEL_CLIENT_WRITE_KEY = {99, 108, 105, 101, 110, 116, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
    public static final byte[] LABEL_SERVER_WRITE_KEY = {115, 101, 114, 118, 101, 114, 32, 119, 114, 105, 116, 101, 32, 107, 101, 121};
    public static final byte[] LABEL_IV_BLOCK = {73, 86, 32, 98, 108, 111, 99, 107};
    public static final byte[] LABEL_MASTER_SECRET = {109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};
    public static final byte[] LABEL_EXTENDED_MASTER_SECRET = {101, 120, 116, 101, 110, 100, 101, 100, 32, 109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116};

    private static final int RANDOM_DATA_LENGTH = 32;
    
    public static byte[] randomData() {
        try {
            var data = new byte[RANDOM_DATA_LENGTH];
            SecureRandom.getInstanceStrong()
                    .nextBytes(data);
            return data;
        }catch (NoSuchAlgorithmException _) {
            throw new TlsAlert("No secure RNG algorithm", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
    }
}
