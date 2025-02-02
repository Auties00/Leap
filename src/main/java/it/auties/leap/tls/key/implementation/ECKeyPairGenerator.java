package it.auties.leap.tls.key.implementation;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsKeyPairGenerator;
import it.auties.leap.tls.version.TlsVersion;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class ECKeyPairGenerator implements TlsKeyPairGenerator {
    private static final ECKeyPairGenerator SECT163K1 = new ECKeyPairGenerator("sect163k1");
    private static final ECKeyPairGenerator SECT163R1 = new ECKeyPairGenerator("sect163r1");
    private static final ECKeyPairGenerator SECT163R2 = new ECKeyPairGenerator("sect163r2");
    private static final ECKeyPairGenerator SECT193R1 = new ECKeyPairGenerator("sect193r1");
    private static final ECKeyPairGenerator SECT193R2 = new ECKeyPairGenerator("sect193r2");
    private static final ECKeyPairGenerator SECT233K1 = new ECKeyPairGenerator("sect233k1");
    private static final ECKeyPairGenerator SECT233R1 = new ECKeyPairGenerator("sect233r1");
    private static final ECKeyPairGenerator SECT239K1 = new ECKeyPairGenerator("sect239k1");
    private static final ECKeyPairGenerator SECT283K1 = new ECKeyPairGenerator("sect283k1");
    private static final ECKeyPairGenerator SECT283R1 = new ECKeyPairGenerator("sect283r1");
    private static final ECKeyPairGenerator SECT409K1 = new ECKeyPairGenerator("sect409k1");
    private static final ECKeyPairGenerator SECT409R1 = new ECKeyPairGenerator("sect409r1");
    private static final ECKeyPairGenerator SECT571K1 = new ECKeyPairGenerator("sect571k1");
    private static final ECKeyPairGenerator SECT571R1 = new ECKeyPairGenerator("sect571r1");
    private static final ECKeyPairGenerator SECP160K1 = new ECKeyPairGenerator("secp160k1");
    private static final ECKeyPairGenerator SECP160R1 = new ECKeyPairGenerator("secp160r1");
    private static final ECKeyPairGenerator SECP160R2 = new ECKeyPairGenerator("secp160r2");
    private static final ECKeyPairGenerator SECP192K1 = new ECKeyPairGenerator("secp192k1");
    private static final ECKeyPairGenerator SECP192R1 = new ECKeyPairGenerator("secp192r1");
    private static final ECKeyPairGenerator SECP224K1 = new ECKeyPairGenerator("secp224k1");
    private static final ECKeyPairGenerator SECP224R1 = new ECKeyPairGenerator("secp224r1");
    private static final ECKeyPairGenerator SECP256K1 = new ECKeyPairGenerator("secp256k1");
    private static final ECKeyPairGenerator SECP256R1 = new ECKeyPairGenerator("secp256r1");
    private static final ECKeyPairGenerator SECP384R1 = new ECKeyPairGenerator("secp384r1");
    private static final ECKeyPairGenerator SECP521R1 = new ECKeyPairGenerator("secp521r1");
    private static final ECKeyPairGenerator BRAINPOOLP256R1 = new ECKeyPairGenerator("brainpoolp256r1");
    private static final ECKeyPairGenerator BRAINPOOLP384R1 = new ECKeyPairGenerator("brainpoolp384r1");
    private static final ECKeyPairGenerator BRAINPOOLP512R1 = new ECKeyPairGenerator("brainpoolp512r1");;
    private static final ECKeyPairGenerator GC256A = new ECKeyPairGenerator("gc256a");
    private static final ECKeyPairGenerator GC256B = new ECKeyPairGenerator("gc256b");
    private static final ECKeyPairGenerator GC256C = new ECKeyPairGenerator("gc256c");
    private static final ECKeyPairGenerator GC256D = new ECKeyPairGenerator("gc256d");
    private static final ECKeyPairGenerator GC512A = new ECKeyPairGenerator("gc512a");
    private static final ECKeyPairGenerator GC512B = new ECKeyPairGenerator("gc512b");
    private static final ECKeyPairGenerator GC512C = new ECKeyPairGenerator("gc512c");

    private final String name;

    private ECKeyPairGenerator(String name) {
        this.name = name;
    }

    public static ECKeyPairGenerator sect163k1() {
        return SECT163K1;
    }

    public static ECKeyPairGenerator sect163r1() {
        return SECT163R1;
    }

    public static ECKeyPairGenerator sect163r2() {
        return SECT163R2;
    }

    public static ECKeyPairGenerator sect193r1() {
        return SECT193R1;
    }

    public static ECKeyPairGenerator sect193r2() {
        return SECT193R2;
    }

    public static ECKeyPairGenerator sect233k1() {
        return SECT233K1;
    }

    public static ECKeyPairGenerator sect233r1() {
        return SECT233R1;
    }

    public static ECKeyPairGenerator sect239k1() {
        return SECT239K1;
    }

    public static ECKeyPairGenerator sect283k1() {
        return SECT283K1;
    }

    public static ECKeyPairGenerator sect283r1() {
        return SECT283R1;
    }

    public static ECKeyPairGenerator sect409k1() {
        return SECT409K1;
    }

    public static ECKeyPairGenerator sect409r1() {
        return SECT409R1;
    }

    public static ECKeyPairGenerator sect571k1() {
        return SECT571K1;
    }

    public static ECKeyPairGenerator sect571r1() {
        return SECT571R1;
    }

    public static ECKeyPairGenerator secp160k1() {
        return SECP160K1;
    }

    public static ECKeyPairGenerator secp160r1() {
        return SECP160R1;
    }

    public static ECKeyPairGenerator secp160r2() {
        return SECP160R2;
    }

    public static ECKeyPairGenerator secp192k1() {
        return SECP192K1;
    }

    public static ECKeyPairGenerator secp192r1() {
        return SECP192R1;
    }

    public static ECKeyPairGenerator secp224k1() {
        return SECP224K1;
    }

    public static ECKeyPairGenerator secp224r1() {
        return SECP224R1;
    }

    public static ECKeyPairGenerator secp256k1() {
        return SECP256K1;
    }

    public static ECKeyPairGenerator secp256r1() {
        return SECP256R1;
    }

    public static ECKeyPairGenerator secp384r1() {
        return SECP384R1;
    }

    public static ECKeyPairGenerator secp521r1() {
        return SECP521R1;
    }

    public static ECKeyPairGenerator brainpoolp256r1() {
        return BRAINPOOLP256R1;
    }

    public static ECKeyPairGenerator brainpoolp384r1() {
        return BRAINPOOLP384R1;
    }

    public static ECKeyPairGenerator brainpoolp512r1() {
        return BRAINPOOLP512R1;
    }

    public static ECKeyPairGenerator gc256a() {
        return GC256A;
    }

    public static ECKeyPairGenerator gc256b() {
        return GC256B;
    }

    public static ECKeyPairGenerator gc256c() {
        return GC256C;
    }

    public static ECKeyPairGenerator gc256d() {
        return GC256D;
    }

    public static ECKeyPairGenerator gc512a() {
        return GC512A;
    }

    public static ECKeyPairGenerator gc512b() {
        return GC512B;
    }

    public static ECKeyPairGenerator gc512c() {
        return GC512C;
    }

    @Override
    public KeyPair generate(TlsVersion version) {
        try {
            var ecSpec = ECNamedCurveTable.getParameterSpec(name);
            var keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(ecSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new TlsException("Cannot generate EC keypair", exception);
        }
    }
}
