package it.auties.leap.tls.config;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.extension.TlsExtension;

import java.util.List;
import java.util.Objects;

public final class TlsGrease {
    private static final TlsGrease GREASE_0A = new TlsGrease(TlsVersionId.grease0A(), TlsCipher.grease0A(), TlsExtension.grease0A());
    private static final TlsGrease GREASE_1A = new TlsGrease(TlsVersionId.grease1A(), TlsCipher.grease1A(), TlsExtension.grease1A());
    private static final TlsGrease GREASE_2A = new TlsGrease(TlsVersionId.grease2A(), TlsCipher.grease2A(), TlsExtension.grease2A());
    private static final TlsGrease GREASE_3A = new TlsGrease(TlsVersionId.grease3A(), TlsCipher.grease3A(), TlsExtension.grease3A());
    private static final TlsGrease GREASE_4A = new TlsGrease(TlsVersionId.grease4A(), TlsCipher.grease4A(), TlsExtension.grease4A());
    private static final TlsGrease GREASE_5A = new TlsGrease(TlsVersionId.grease5A(), TlsCipher.grease5A(), TlsExtension.grease5A());
    private static final TlsGrease GREASE_6A = new TlsGrease(TlsVersionId.grease6A(), TlsCipher.grease6A(), TlsExtension.grease6A());
    private static final TlsGrease GREASE_7A = new TlsGrease(TlsVersionId.grease7A(), TlsCipher.grease7A(), TlsExtension.grease7A());
    private static final TlsGrease GREASE_8A = new TlsGrease(TlsVersionId.grease8A(), TlsCipher.grease8A(), TlsExtension.grease8A());
    private static final TlsGrease GREASE_9A = new TlsGrease(TlsVersionId.grease9A(), TlsCipher.grease9A(), TlsExtension.grease9A());
    private static final TlsGrease GREASE_AA = new TlsGrease(TlsVersionId.greaseAA(), TlsCipher.greaseAA(), TlsExtension.greaseAA());
    private static final TlsGrease GREASE_BA = new TlsGrease(TlsVersionId.greaseBA(), TlsCipher.greaseBA(), TlsExtension.greaseBA());
    private static final TlsGrease GREASE_CA = new TlsGrease(TlsVersionId.greaseCA(), TlsCipher.greaseCA(), TlsExtension.greaseCA());
    private static final TlsGrease GREASE_DA = new TlsGrease(TlsVersionId.greaseDA(), TlsCipher.greaseDA(), TlsExtension.greaseDA());
    private static final TlsGrease GREASE_EA = new TlsGrease(TlsVersionId.greaseEA(), TlsCipher.greaseEA(), TlsExtension.greaseEA());
    private static final TlsGrease GREASE_FA = new TlsGrease(TlsVersionId.greaseFA(), TlsCipher.greaseFA(), TlsExtension.greaseFA());
    private static final List<TlsGrease> VALUES = List.of(GREASE_0A, GREASE_1A, GREASE_2A, GREASE_3A, GREASE_4A, GREASE_5A, GREASE_6A, GREASE_7A, GREASE_8A, GREASE_9A, GREASE_AA, GREASE_BA, GREASE_CA, GREASE_DA, GREASE_EA, GREASE_FA);

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

    public static List<TlsGrease> values() {
        return VALUES;
    }

    public static boolean isGrease(int extensionType) {
        return (extensionType & 0x0f0f) == 0x0a0a;
    }

    private final TlsVersionId versionId;
    private final TlsCipher cipher;
    private final TlsExtension extension;

    private TlsGrease(TlsVersionId versionId, TlsCipher cipher, TlsExtension extension) {
        this.versionId = versionId;
        this.cipher = cipher;
        this.extension = extension;
    }

    public TlsVersionId versionId() {
        return versionId;
    }

    public TlsCipher cipher() {
        return cipher;
    }

    public TlsExtension extension() {
        return extension;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TlsGrease) obj;
        return Objects.equals(this.versionId, that.versionId) &&
                Objects.equals(this.cipher, that.cipher) &&
                Objects.equals(this.extension, that.extension);
    }

    @Override
    public int hashCode() {
        return Objects.hash(versionId, cipher, extension);
    }

    @Override
    public String toString() {
        return "TlsGrease[" +
                "versionId=" + versionId + ", " +
                "cipher=" + cipher + ", " +
                "extension=" + extension + ']';
    }
}
