package it.auties.leap.tls.key;

import it.auties.leap.tls.key.implementation.*;
import it.auties.leap.tls.version.TlsVersion;

import java.security.KeyPair;

public interface TlsKeyPairGenerator {
    KeyPair generate(TlsVersion version);

    static TlsKeyPairGenerator unsupported() {
        return UnsupportedKeyPairGenerator.instance();
    }

    static TlsKeyPairGenerator x25519() {
        return XDHKeyPairGenerator.x25519();
    }

    static TlsKeyPairGenerator x448() {
        return XDHKeyPairGenerator.x448();
    }

    static TlsKeyPairGenerator ecdsa() {
        return XDHKeyPairGenerator.x448();
    }

    static TlsKeyPairGenerator sect163k1() {
        return ECDSAKeyPairGenerator.sect163k1();
    }

    static TlsKeyPairGenerator sect163r1() {
        return ECDSAKeyPairGenerator.sect163r1();
    }

    static TlsKeyPairGenerator sect163r2() {
        return ECDSAKeyPairGenerator.sect163r2();
    }

    static TlsKeyPairGenerator sect193r1() {
        return ECDSAKeyPairGenerator.sect193r1();
    }

    static TlsKeyPairGenerator sect193r2() {
        return ECDSAKeyPairGenerator.sect193r2();
    }

    static TlsKeyPairGenerator sect233k1() {
        return ECDSAKeyPairGenerator.sect233k1();
    }

    static TlsKeyPairGenerator sect233r1() {
        return ECDSAKeyPairGenerator.sect233r1();
    }

    static TlsKeyPairGenerator sect239k1() {
        return ECDSAKeyPairGenerator.sect239k1();
    }

    static TlsKeyPairGenerator sect283k1() {
        return ECDSAKeyPairGenerator.sect283k1();
    }

    static TlsKeyPairGenerator sect283r1() {
        return ECDSAKeyPairGenerator.sect283r1();
    }

    static TlsKeyPairGenerator sect409k1() {
        return ECDSAKeyPairGenerator.sect409k1();
    }

    static TlsKeyPairGenerator sect409r1() {
        return ECDSAKeyPairGenerator.sect409r1();
    }

    static TlsKeyPairGenerator sect571k1() {
        return ECDSAKeyPairGenerator.sect571k1();
    }

    static TlsKeyPairGenerator sect571r1() {
        return ECDSAKeyPairGenerator.sect571r1();
    }

    static TlsKeyPairGenerator secp160k1() {
        return ECDSAKeyPairGenerator.secp160k1();
    }

    static TlsKeyPairGenerator secp160r1() {
        return ECDSAKeyPairGenerator.secp160r1();
    }

    static TlsKeyPairGenerator secp160r2() {
        return ECDSAKeyPairGenerator.secp160r2();
    }

    static TlsKeyPairGenerator secp192k1() {
        return ECDSAKeyPairGenerator.secp192k1();
    }

    static TlsKeyPairGenerator secp192r1() {
        return ECDSAKeyPairGenerator.secp192r1();
    }

    static TlsKeyPairGenerator secp224k1() {
        return ECDSAKeyPairGenerator.secp224k1();
    }

    static TlsKeyPairGenerator secp224r1() {
        return ECDSAKeyPairGenerator.secp224r1();
    }

    static TlsKeyPairGenerator secp256k1() {
        return ECDSAKeyPairGenerator.secp256k1();
    }

    static TlsKeyPairGenerator secp256r1() {
        return ECDSAKeyPairGenerator.secp256r1();
    }

    static TlsKeyPairGenerator secp384r1() {
        return ECDSAKeyPairGenerator.secp384r1();
    }

    static TlsKeyPairGenerator secp521r1() {
        return ECDSAKeyPairGenerator.secp521r1();
    }

    static TlsKeyPairGenerator brainpoolp256r1() {
        return ECDSAKeyPairGenerator.brainpoolp256r1();
    }

    static TlsKeyPairGenerator brainpoolp384r1() {
        return ECDSAKeyPairGenerator.brainpoolp384r1();
    }

    static TlsKeyPairGenerator brainpoolp512r1() {
        return ECDSAKeyPairGenerator.brainpoolp512r1();
    }

    static TlsKeyPairGenerator gc256a() {
        return ECDSAKeyPairGenerator.gc256a();
    }

    static TlsKeyPairGenerator gc256b() {
        return ECDSAKeyPairGenerator.gc256b();
    }

    static TlsKeyPairGenerator gc256c() {
        return ECDSAKeyPairGenerator.gc256c();
    }

    static TlsKeyPairGenerator gc256d() {
        return ECDSAKeyPairGenerator.gc256d();
    }

    static TlsKeyPairGenerator gc512a() {
        return ECDSAKeyPairGenerator.gc512a();
    }

    static TlsKeyPairGenerator gc512b() {
        return ECDSAKeyPairGenerator.gc512b();
    }

    static TlsKeyPairGenerator gc512c() {
        return ECDSAKeyPairGenerator.gc512c();
    }

    static TlsKeyPairGenerator ffdhe2048() {
        return DHKeyPairGenerator.ffdhe2048();
    }

    static TlsKeyPairGenerator ffdhe3072() {
        return DHKeyPairGenerator.ffdhe3072();
    }

    static TlsKeyPairGenerator ffdhe4096() {
        return DHKeyPairGenerator.ffdhe4096();
    }

    static TlsKeyPairGenerator ffdhe6144() {
        return DHKeyPairGenerator.ffdhe6144();
    }

    static TlsKeyPairGenerator ffdhe8192() {
        return DHKeyPairGenerator.ffdhe8192();
    }

    static TlsKeyPairGenerator mlKem512() {
        return MLKEMKeyPairGenerator.mlKem512();
    }

    static TlsKeyPairGenerator mlKem768() {
        return MLKEMKeyPairGenerator.mlKem768();
    }

    static TlsKeyPairGenerator mlKem1024() {
        return MLKEMKeyPairGenerator.mlKem1024();
    }
}
