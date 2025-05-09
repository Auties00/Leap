package it.auties.leap.tls.ciphersuite;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngine;
import it.auties.leap.tls.ciphersuite.engine.TlsCipherEngineFactory;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipherFactory;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;
import it.auties.leap.tls.version.TlsVersions;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

public final class TlsGrease {
    private static final TlsCipherEngineFactory ENGINE_FACTORY = new TlsCipherEngineFactory() {
        @Override
        public TlsCipherEngine newCipherEngine(boolean forEncryption, byte[] key) {
            return throwOnUsage();
        }

        @Override
        public int keyLength() {
            return throwOnUsage();
        }

        @Override
        public int blockLength() {
            return throwOnUsage();
        }
    };

    private static final TlsCipherFactory MODE_FACTORY = _ -> throwOnUsage();

    private static <T> T throwOnUsage() {
        throw new TlsAlert("GREASE cipher should not be selected", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
    }

    private static final TlsGrease GREASE_0A = new TlsGrease(TlsVersionId.of(0x0A0A), createGREASECipher(0x0A0A));
    private static final TlsGrease GREASE_1A = new TlsGrease(TlsVersionId.of(0x1A1A), createGREASECipher(0x1A1A));
    private static final TlsGrease GREASE_2A = new TlsGrease(TlsVersionId.of(0x2A2A), createGREASECipher(0x2A2A));
    private static final TlsGrease GREASE_3A = new TlsGrease(TlsVersionId.of(0x3A3A), createGREASECipher(0x3A3A));
    private static final TlsGrease GREASE_4A = new TlsGrease(TlsVersionId.of(0x4A4A), createGREASECipher(0x4A4A));
    private static final TlsGrease GREASE_5A = new TlsGrease(TlsVersionId.of(0x5A5A), createGREASECipher(0x5A5A));
    private static final TlsGrease GREASE_6A = new TlsGrease(TlsVersionId.of(0x6A6A), createGREASECipher(0x6A6A));
    private static final TlsGrease GREASE_7A = new TlsGrease(TlsVersionId.of(0x7A7A), createGREASECipher(0x7A7A));
    private static final TlsGrease GREASE_8A = new TlsGrease(TlsVersionId.of(0x8A8A), createGREASECipher(0x8A8A));
    private static final TlsGrease GREASE_9A = new TlsGrease(TlsVersionId.of(0x9A9A), createGREASECipher(0x9A9A));
    private static final TlsGrease GREASE_AA = new TlsGrease(TlsVersionId.of(0xAAAA), createGREASECipher(0xAAAA));
    private static final TlsGrease GREASE_BA = new TlsGrease(TlsVersionId.of(0xBABA), createGREASECipher(0xBABA));
    private static final TlsGrease GREASE_CA = new TlsGrease(TlsVersionId.of(0xCACA), createGREASECipher(0xCACA));
    private static final TlsGrease GREASE_DA = new TlsGrease(TlsVersionId.of(0xDADA), createGREASECipher(0xDADA));
    private static final TlsGrease GREASE_EA = new TlsGrease(TlsVersionId.of(0xEAEA), createGREASECipher(0xEAEA));
    private static final TlsGrease GREASE_FA = new TlsGrease(TlsVersionId.of(0xFAFA), createGREASECipher(0xFAFA));
    private static final List<TlsGrease> VALUES = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);

    private static TlsCipherSuite createGREASECipher(int id) {
        return new TlsCipherSuite(
                id,
                ENGINE_FACTORY,
                MODE_FACTORY,
                null,
                null,
                TlsHashFactory.none(),
                TlsVersions.range(TlsVersion.TLS12, TlsVersion.TLS13)
        );
    }

    public static TlsGrease grease0A() {
        return GREASE_0A;
    }

    public static TlsGrease grease1A() {
        return GREASE_1A;
    }

    public static TlsGrease grease2A() {
        return GREASE_2A;
    }

    public static TlsGrease grease3A() {
        return GREASE_3A;
    }

    public static TlsGrease grease4A() {
        return GREASE_4A;
    }

    public static TlsGrease grease5A() {
        return GREASE_5A;
    }

    public static TlsGrease grease6A() {
        return GREASE_6A;
    }

    public static TlsGrease grease7A() {
        return GREASE_7A;
    }

    public static TlsGrease grease8A() {
        return GREASE_8A;
    }

    public static TlsGrease grease9A() {
        return GREASE_9A;
    }

    public static TlsGrease greaseAA() {
        return GREASE_AA;
    }

    public static TlsGrease greaseBA() {
        return GREASE_BA;
    }

    public static TlsGrease greaseCA() {
        return GREASE_CA;
    }

    public static TlsGrease greaseDA() {
        return GREASE_DA;
    }

    public static TlsGrease greaseEA() {
        return GREASE_EA;
    }

    public static TlsGrease greaseFA() {
        return GREASE_FA;
    }

    public static TlsVersionId greaseRandom() {
        try {
            var values = TlsGrease.values();
            var index = SecureRandom.getInstanceStrong()
                    .nextInt(0, values.size());
            return values.get(index)
                    .versionId();
        }catch (NoSuchAlgorithmException throwable) {
            throw new RuntimeException("No secure RNG algorithm", throwable);
        }
    }

    public static List<TlsGrease> values() {
        return VALUES;
    }

    public static boolean isGrease(int extensionType) {
        return (extensionType & 0x0f0f) == 0x0a0a;
    }

    private final TlsVersionId versionId;
    private final TlsCipherSuite cipher;

    private TlsGrease(TlsVersionId versionId, TlsCipherSuite cipher) {
        this.versionId = versionId;
        this.cipher = cipher;
    }

    public TlsVersionId versionId() {
        return versionId;
    }

    public TlsCipherSuite cipher() {
        return cipher;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsGrease that
                && Objects.equals(versionId, that.versionId)
                && Objects.equals(cipher, that.cipher);
    }

    @Override
    public int hashCode() {
        return Objects.hash(versionId, cipher);
    }

    @Override
    public String toString() {
        return "TlsGrease[" +
                "id=" + versionId + ']';
    }
}
