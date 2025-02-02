package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;

import java.util.Arrays;

import static it.auties.leap.tls.util.TlsKeyConstants.*;

public final class TlsMasterSecretKey {
    private static final int LENGTH = 48;
    private final byte[] data;
    private TlsMasterSecretKey(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsMasterSecretKey of(
            TlsEngine.Mode mode,
            TlsVersion version,
            TlsCipher cipher,
            byte[] preMasterKey,
            byte[] extendedMasterSecretSessionHash,
            TlsRandomData localRandomData,
            TlsRandomData remoteRandomData
    ) {
        var clientRandom = switch (mode) {
            case CLIENT -> localRandomData.data();
            case SERVER -> remoteRandomData.data();
        };
        var serverRandom = switch (mode) {
            case SERVER -> localRandomData.data();
            case CLIENT -> remoteRandomData.data();
        };
        return switch (version) {
            case SSL30 -> {
                var master = new byte[length()];
                var md5 = TlsHash.md5();
                var sha = TlsHash.sha1();
                var tmp = new byte[20];
                for (var i = 0; i < 3; i++) {
                    sha.update(SSL3_CONSTANT[i]);
                    sha.update(preMasterKey);
                    sha.update(clientRandom);
                    sha.update(serverRandom);
                    sha.digest(tmp, 0, 20, true);
                    md5.update(preMasterKey);
                    md5.update(tmp);
                    md5.digest(master, i << 4, 16, true);
                }
                yield new TlsMasterSecretKey(master);
            }
            case TLS10, TLS11, DTLS10 -> {
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                var result = TlsPRF.tls10Prf(
                        preMasterKey,
                        label,
                        seed,
                        length()
                );
                yield new TlsMasterSecretKey(result);
            }
            case TLS12, DTLS12, TLS13, DTLS13 -> {
                var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
                var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
                var result = TlsPRF.tls12Prf(
                        preMasterKey,
                        label,
                        seed,
                        length(),
                        cipher.hashFactory().newHash()
                );
                yield new TlsMasterSecretKey(result);
            }
        };
    }

    public byte[] data() {
        return data;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsMasterSecretKey) obj;
        return Arrays.equals(this.data, that.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "TlsMasterSecretKey[" +
                "data=" + Arrays.toString(data) + ']';
    }

}
