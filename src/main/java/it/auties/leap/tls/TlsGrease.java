package it.auties.leap.tls;

import java.security.SecureRandom;

public record TlsGrease(TlsVersionId versionId, TlsCipher cipher, TlsExtension extension) {
    private static final TlsGrease[] INSTANCES = new TlsGrease[] {
            new TlsGrease(TlsVersionId.grease0A(), TlsCipher.grease0A(), TlsExtension.grease0A()),
            new TlsGrease(TlsVersionId.grease1A(), TlsCipher.grease1A(), TlsExtension.grease1A()),
            new TlsGrease(TlsVersionId.grease2A(), TlsCipher.grease2A(), TlsExtension.grease2A()),
            new TlsGrease(TlsVersionId.grease3A(), TlsCipher.grease3A(), TlsExtension.grease3A()),
            new TlsGrease(TlsVersionId.grease4A(), TlsCipher.grease4A(), TlsExtension.grease4A()),
            new TlsGrease(TlsVersionId.grease5A(), TlsCipher.grease5A(), TlsExtension.grease5A()),
            new TlsGrease(TlsVersionId.grease6A(), TlsCipher.grease6A(), TlsExtension.grease6A()),
            new TlsGrease(TlsVersionId.grease7A(), TlsCipher.grease7A(), TlsExtension.grease7A()),
            new TlsGrease(TlsVersionId.grease8A(), TlsCipher.grease8A(), TlsExtension.grease8A()),
            new TlsGrease(TlsVersionId.grease9A(), TlsCipher.grease9A(), TlsExtension.grease9A()),
            new TlsGrease(TlsVersionId.greaseAA(), TlsCipher.greaseAA(), TlsExtension.greaseAA()),
            new TlsGrease(TlsVersionId.greaseBA(), TlsCipher.greaseBA(), TlsExtension.greaseBA()),
            new TlsGrease(TlsVersionId.greaseCA(), TlsCipher.greaseCA(), TlsExtension.greaseCA()),
            new TlsGrease(TlsVersionId.greaseDA(), TlsCipher.greaseDA(), TlsExtension.greaseDA()),
            new TlsGrease(TlsVersionId.greaseEA(), TlsCipher.greaseEA(), TlsExtension.greaseEA()),
            new TlsGrease(TlsVersionId.greaseFA(), TlsCipher.greaseFA(), TlsExtension.greaseFA())
    };

    public static TlsGrease grease0A() {
        return INSTANCES[0];
    }

    public static TlsGrease grease1A() {
        return INSTANCES[1];
    }

    public static TlsGrease grease2A() {
        return INSTANCES[2];
    }

    public static TlsGrease grease3A() {
        return INSTANCES[3];
    }

    public static TlsGrease grease4A() {
        return INSTANCES[4];
    }

    public static TlsGrease grease5A() {
        return INSTANCES[5];
    }

    public static TlsGrease grease6A() {
        return INSTANCES[6];
    }

    public static TlsGrease grease7A() {
        return INSTANCES[7];
    }

    public static TlsGrease grease8A() {
        return INSTANCES[8];
    }

    public static TlsGrease grease9A() {
        return INSTANCES[9];
    }

    public static TlsGrease greaseAA() {
        return INSTANCES[10];
    }

    public static TlsGrease greaseBA() {
        return INSTANCES[11];
    }

    public static TlsGrease greaseCA() {
        return INSTANCES[12];
    }

    public static TlsGrease greaseDA() {
        return INSTANCES[13];
    }

    public static TlsGrease greaseEA() {
        return INSTANCES[14];
    }

    public static TlsGrease greaseFA() {
        return INSTANCES[15];
    }

    public static TlsGrease grease(int index) {
        if(index < 0 || index >= INSTANCES.length) {
            throw new IndexOutOfBoundsException("Index %s is not within bounds [0, 16)".formatted(index));
        }

        return INSTANCES[index];
    }

    public static TlsGrease grease() {
        var random = new SecureRandom();
        return INSTANCES[random.nextInt(0, INSTANCES.length)];
    }
}
