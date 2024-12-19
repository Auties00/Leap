package it.auties.leap.tls.key;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;
import it.auties.leap.tls.config.TlsMode;

import static it.auties.leap.tls.key.TlsKeyConstants.*;

public record TlsMasterSecretKey(byte[] data) {
    private static final int LENGTH = 48;

    public static int length() {
        return LENGTH;
    }

    public static TlsMasterSecretKey of(
            TlsMode mode,
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
        if (version == TlsVersion.SSL30) {
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
            return new TlsMasterSecretKey(master);
        }

        var label = extendedMasterSecretSessionHash != null ? LABEL_EXTENDED_MASTER_SECRET : LABEL_MASTER_SECRET;
        var seed = extendedMasterSecretSessionHash != null ? extendedMasterSecretSessionHash : TlsPRF.seed(clientRandom, serverRandom);
        if (version == TlsVersion.TLS10 || version == TlsVersion.TLS11) {
            var result = TlsPRF.tls10Prf(
                    preMasterKey,
                    label,
                    seed,
                    length()
            );
            return new TlsMasterSecretKey(result);
        }

        var result = TlsPRF.tls12Prf(
                preMasterKey,
                label,
                seed,
                length(),
                cipher.hashSupplier().get()
        );
        return new TlsMasterSecretKey(result);
    }
}
