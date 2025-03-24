package it.auties.leap.tls.secret;

import it.auties.leap.tls.TlsMode;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.hash.TlsHash;
import it.auties.leap.tls.hash.TlsPRF;

import java.util.Arrays;

import static it.auties.leap.tls.util.TlsKeyUtils.*;

public final class TlsMasterSecret {
    private static final int LENGTH = 48;
    private final byte[] data;
    private TlsMasterSecret(byte[] data) {
        this.data = data;
    }

    public static int length() {
        return LENGTH;
    }

    public static TlsMasterSecret of(
            TlsMode mode,
            TlsVersion version,
            TlsCipher cipher,
            byte[] preMasterKey,
            byte[] extendedMasterSecretSessionHash,
            byte[] localRandomData,
            byte[] remoteRandomData
    ) {
        var clientRandom = switch (mode) {
            case CLIENT -> localRandomData;
            case SERVER -> remoteRandomData;
        };
        var serverRandom = switch (mode) {
            case SERVER -> localRandomData;
            case CLIENT -> remoteRandomData;
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
                yield new TlsMasterSecret(master);
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
                yield new TlsMasterSecret(result);
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
                yield new TlsMasterSecret(result);
            }
        };
    }

    public byte[] data() {
        return data;
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this
                || (obj instanceof TlsMasterSecret that && Arrays.equals(this.data, that.data));
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
