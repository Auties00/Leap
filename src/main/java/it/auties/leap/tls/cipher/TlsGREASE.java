package it.auties.leap.tls.cipher;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.auth.TlsAuthFactory;
import it.auties.leap.tls.cipher.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.mode.TlsCipherModeFactory;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

public final class TlsGREASE {
    private static final TlsCipherEngineFactory ENGINE_FACTORY = () -> { throw new TlsAlert("GREASE cipher should not be selected"); };
    private static final TlsCipherModeFactory MODE_FACTORY = _ -> { throw new TlsAlert("GREASE cipher should not be selected"); };

    private static final TlsGREASE GREASE_0A = new TlsGREASE(TlsVersionId.of(0x0A0A), createGREASECipher(0x0A0A));
    private static final TlsGREASE GREASE_1A = new TlsGREASE(TlsVersionId.of(0x1A1A), createGREASECipher(0x1A1A));
    private static final TlsGREASE GREASE_2A = new TlsGREASE(TlsVersionId.of(0x2A2A), createGREASECipher(0x2A2A));
    private static final TlsGREASE GREASE_3A = new TlsGREASE(TlsVersionId.of(0x3A3A), createGREASECipher(0x3A3A));
    private static final TlsGREASE GREASE_4A = new TlsGREASE(TlsVersionId.of(0x4A4A), createGREASECipher(0x4A4A));
    private static final TlsGREASE GREASE_5A = new TlsGREASE(TlsVersionId.of(0x5A5A), createGREASECipher(0x5A5A));
    private static final TlsGREASE GREASE_6A = new TlsGREASE(TlsVersionId.of(0x6A6A), createGREASECipher(0x6A6A));
    private static final TlsGREASE GREASE_7A = new TlsGREASE(TlsVersionId.of(0x7A7A), createGREASECipher(0x7A7A));
    private static final TlsGREASE GREASE_8A = new TlsGREASE(TlsVersionId.of(0x8A8A), createGREASECipher(0x8A8A));
    private static final TlsGREASE GREASE_9A = new TlsGREASE(TlsVersionId.of(0x9A9A), createGREASECipher(0x9A9A));
    private static final TlsGREASE GREASE_AA = new TlsGREASE(TlsVersionId.of(0xAAAA), createGREASECipher(0xAAAA));
    private static final TlsGREASE GREASE_BA = new TlsGREASE(TlsVersionId.of(0xBABA), createGREASECipher(0xBABA));
    private static final TlsGREASE GREASE_CA = new TlsGREASE(TlsVersionId.of(0xCACA), createGREASECipher(0xCACA));
    private static final TlsGREASE GREASE_DA = new TlsGREASE(TlsVersionId.of(0xDADA), createGREASECipher(0xDADA));
    private static final TlsGREASE GREASE_EA = new TlsGREASE(TlsVersionId.of(0xEAEA), createGREASECipher(0xEAEA));
    private static final TlsGREASE GREASE_FA = new TlsGREASE(TlsVersionId.of(0xFAFA), createGREASECipher(0xFAFA));
    private static final List<TlsGREASE> VALUES = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);

    private static TlsCipher createGREASECipher(int id) {
        return new TlsCipher(
                id,
                ENGINE_FACTORY,
                MODE_FACTORY,
                TlsKeyExchangeFactory.contextual(),
                TlsAuthFactory.contextual(),
                TlsHashFactory.none(),
                List.of(TlsVersion.TLS12, TlsVersion.TLS13),
                false
        );
    }

    public static TlsGREASE grease0A() {
        return GREASE_0A;
    }

    public static TlsGREASE grease1A() {
        return GREASE_1A;
    }

    public static TlsGREASE grease2A() {
        return GREASE_2A;
    }

    public static TlsGREASE grease3A() {
        return GREASE_3A;
    }

    public static TlsGREASE grease4A() {
        return GREASE_4A;
    }

    public static TlsGREASE grease5A() {
        return GREASE_5A;
    }

    public static TlsGREASE grease6A() {
        return GREASE_6A;
    }

    public static TlsGREASE grease7A() {
        return GREASE_7A;
    }

    public static TlsGREASE grease8A() {
        return GREASE_8A;
    }

    public static TlsGREASE grease9A() {
        return GREASE_9A;
    }

    public static TlsGREASE greaseAA() {
        return GREASE_AA;
    }

    public static TlsGREASE greaseBA() {
        return GREASE_BA;
    }

    public static TlsGREASE greaseCA() {
        return GREASE_CA;
    }

    public static TlsGREASE greaseDA() {
        return GREASE_DA;
    }

    public static TlsGREASE greaseEA() {
        return GREASE_EA;
    }

    public static TlsGREASE greaseFA() {
        return GREASE_FA;
    }

    public static TlsVersionId greaseRandom() {
        try {
            var values = TlsGREASE.values();
            var index = SecureRandom.getInstanceStrong()
                    .nextInt(0, values.size());
            return values.get(index)
                    .versionId();
        }catch (NoSuchAlgorithmException _) {
            throw TlsAlert.noSecureRandom();
        }
    }

    public static List<TlsGREASE> values() {
        return VALUES;
    }
    
    public static boolean isGrease(int extensionType) {
        return (extensionType & 0x0f0f) == 0x0a0a;
    }

    private final TlsVersionId versionId;
    private final TlsCipher cipher;

    private TlsGREASE(TlsVersionId versionId, TlsCipher cipher) {
        this.versionId = versionId;
        this.cipher = cipher;
    }

    public TlsVersionId versionId() {
        return versionId;
    }

    public TlsCipher cipher() {
        return cipher;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsGREASE) obj;
        return Objects.equals(this.versionId, that.versionId) &&
                Objects.equals(this.cipher, that.cipher);
    }

    @Override
    public int hashCode() {
        return Objects.hash(versionId, cipher);
    }

    @Override
    public String toString() {
        return "TlsGrease[" +
                "versionId=" + versionId + ", " +
                "cipher=" + cipher + ']';
    }
}
