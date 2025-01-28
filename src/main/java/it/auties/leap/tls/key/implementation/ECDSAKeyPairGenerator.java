package it.auties.leap.tls.key.implementation;

import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsKeyPairGenerator;
import it.auties.leap.tls.version.TlsVersion;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class ECDSAKeyPairGenerator implements TlsKeyPairGenerator {
    private static final ECDSAKeyPairGenerator SECT163K1 = new ECDSAKeyPairGenerator("sect163k1");
    private static final ECDSAKeyPairGenerator SECT163R1 = new ECDSAKeyPairGenerator("sect163r1");
    private static final ECDSAKeyPairGenerator SECT163R2 = new ECDSAKeyPairGenerator("sect163r2");
    private static final ECDSAKeyPairGenerator SECT193R1 = new ECDSAKeyPairGenerator("sect193r1");
    private static final ECDSAKeyPairGenerator SECT193R2 = new ECDSAKeyPairGenerator("sect193r2");
    private static final ECDSAKeyPairGenerator SECT233K1 = new ECDSAKeyPairGenerator("sect233k1");
    private static final ECDSAKeyPairGenerator SECT233R1 = new ECDSAKeyPairGenerator("sect233r1");
    private static final ECDSAKeyPairGenerator SECT239K1 = new ECDSAKeyPairGenerator("sect239k1");
    private static final ECDSAKeyPairGenerator SECT283K1 = new ECDSAKeyPairGenerator("sect283k1");
    private static final ECDSAKeyPairGenerator SECT283R1 = new ECDSAKeyPairGenerator("sect283r1");
    private static final ECDSAKeyPairGenerator SECT409K1 = new ECDSAKeyPairGenerator("sect409k1");
    private static final ECDSAKeyPairGenerator SECT409R1 = new ECDSAKeyPairGenerator("sect409r1");
    private static final ECDSAKeyPairGenerator SECT571K1 = new ECDSAKeyPairGenerator("sect571k1");
    private static final ECDSAKeyPairGenerator SECT571R1 = new ECDSAKeyPairGenerator("sect571r1");
    private static final ECDSAKeyPairGenerator SECP160K1 = new ECDSAKeyPairGenerator("secp160k1");
    private static final ECDSAKeyPairGenerator SECP160R1 = new ECDSAKeyPairGenerator("secp160r1");
    private static final ECDSAKeyPairGenerator SECP160R2 = new ECDSAKeyPairGenerator("secp160r2");
    private static final ECDSAKeyPairGenerator SECP192K1 = new ECDSAKeyPairGenerator("secp192k1");
    private static final ECDSAKeyPairGenerator SECP192R1 = new ECDSAKeyPairGenerator("secp192r1");
    private static final ECDSAKeyPairGenerator SECP224K1 = new ECDSAKeyPairGenerator("secp224k1");
    private static final ECDSAKeyPairGenerator SECP224R1 = new ECDSAKeyPairGenerator("secp224r1");
    private static final ECDSAKeyPairGenerator SECP256K1 = new ECDSAKeyPairGenerator("secp256k1");
    private static final ECDSAKeyPairGenerator SECP256R1 = new ECDSAKeyPairGenerator("secp256r1");
    private static final ECDSAKeyPairGenerator SECP384R1 = new ECDSAKeyPairGenerator("secp384r1");
    private static final ECDSAKeyPairGenerator SECP521R1 = new ECDSAKeyPairGenerator("secp521r1");
    private static final ECDSAKeyPairGenerator BRAINPOOLP256R1 = new ECDSAKeyPairGenerator("brainpoolp256r1");
    private static final ECDSAKeyPairGenerator BRAINPOOLP384R1 = new ECDSAKeyPairGenerator("brainpoolp384r1");
    private static final ECDSAKeyPairGenerator BRAINPOOLP512R1 = new ECDSAKeyPairGenerator("brainpoolp512r1");;
    private static final ECDSAKeyPairGenerator GC256A = new ECDSAKeyPairGenerator("gc256a");
    private static final ECDSAKeyPairGenerator GC256B = new ECDSAKeyPairGenerator("gc256b");
    private static final ECDSAKeyPairGenerator GC256C = new ECDSAKeyPairGenerator("gc256c");
    private static final ECDSAKeyPairGenerator GC256D = new ECDSAKeyPairGenerator("gc256d");
    private static final ECDSAKeyPairGenerator GC512A = new ECDSAKeyPairGenerator("gc512a");
    private static final ECDSAKeyPairGenerator GC512B = new ECDSAKeyPairGenerator("gc512b");
    private static final ECDSAKeyPairGenerator GC512C = new ECDSAKeyPairGenerator("gc512c");

    private final String name;

    private ECDSAKeyPairGenerator(String name) {
        this.name = name;
    }

    public static ECDSAKeyPairGenerator sect163k1() {
        return SECT163K1;
    }

    public static ECDSAKeyPairGenerator sect163r1() {
        return SECT163R1;
    }

    public static ECDSAKeyPairGenerator sect163r2() {
        return SECT163R2;
    }

    public static ECDSAKeyPairGenerator sect193r1() {
        return SECT193R1;
    }

    public static ECDSAKeyPairGenerator sect193r2() {
        return SECT193R2;
    }

    public static ECDSAKeyPairGenerator sect233k1() {
        return SECT233K1;
    }

    public static ECDSAKeyPairGenerator sect233r1() {
        return SECT233R1;
    }

    public static ECDSAKeyPairGenerator sect239k1() {
        return SECT239K1;
    }

    public static ECDSAKeyPairGenerator sect283k1() {
        return SECT283K1;
    }

    public static ECDSAKeyPairGenerator sect283r1() {
        return SECT283R1;
    }

    public static ECDSAKeyPairGenerator sect409k1() {
        return SECT409K1;
    }

    public static ECDSAKeyPairGenerator sect409r1() {
        return SECT409R1;
    }

    public static ECDSAKeyPairGenerator sect571k1() {
        return SECT571K1;
    }

    public static ECDSAKeyPairGenerator sect571r1() {
        return SECT571R1;
    }

    public static ECDSAKeyPairGenerator secp160k1() {
        return SECP160K1;
    }

    public static ECDSAKeyPairGenerator secp160r1() {
        return SECP160R1;
    }

    public static ECDSAKeyPairGenerator secp160r2() {
        return SECP160R2;
    }

    public static ECDSAKeyPairGenerator secp192k1() {
        return SECP192K1;
    }

    public static ECDSAKeyPairGenerator secp192r1() {
        return SECP192R1;
    }

    public static ECDSAKeyPairGenerator secp224k1() {
        return SECP224K1;
    }

    public static ECDSAKeyPairGenerator secp224r1() {
        return SECP224R1;
    }

    public static ECDSAKeyPairGenerator secp256k1() {
        return SECP256K1;
    }

    public static ECDSAKeyPairGenerator secp256r1() {
        return SECP256R1;
    }

    public static ECDSAKeyPairGenerator secp384r1() {
        return SECP384R1;
    }

    public static ECDSAKeyPairGenerator secp521r1() {
        return SECP521R1;
    }

    public static ECDSAKeyPairGenerator brainpoolp256r1() {
        return BRAINPOOLP256R1;
    }

    public static ECDSAKeyPairGenerator brainpoolp384r1() {
        return BRAINPOOLP384R1;
    }

    public static ECDSAKeyPairGenerator brainpoolp512r1() {
        return BRAINPOOLP512R1;
    }

    public static ECDSAKeyPairGenerator gc256a() {
        return GC256A;
    }

    public static ECDSAKeyPairGenerator gc256b() {
        return GC256B;
    }

    public static ECDSAKeyPairGenerator gc256c() {
        return GC256C;
    }

    public static ECDSAKeyPairGenerator gc256d() {
        return GC256D;
    }

    public static ECDSAKeyPairGenerator gc512a() {
        return GC512A;
    }

    public static ECDSAKeyPairGenerator gc512b() {
        return GC512B;
    }

    public static ECDSAKeyPairGenerator gc512c() {
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
