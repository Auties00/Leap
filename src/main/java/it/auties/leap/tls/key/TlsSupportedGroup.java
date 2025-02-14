package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.groups.ExplicitChar2;
import it.auties.leap.tls.key.groups.ExplicitPrime;
import it.auties.leap.tls.key.groups.NamedCurve;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Optional;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public interface TlsSupportedGroup {
    static TlsSupportedGroup sect163k1() {
        return NamedCurve.sect163k1();
    }

    static TlsSupportedGroup sect163r1() {
        return NamedCurve.sect163r1();
    }

    static TlsSupportedGroup sect163r2() {
        return NamedCurve.sect163r2();
    }

    static TlsSupportedGroup sect193r1() {
        return NamedCurve.sect193r1();
    }

    static TlsSupportedGroup sect193r2() {
        return NamedCurve.sect193r2();
    }

    static TlsSupportedGroup sect233k1() {
        return NamedCurve.sect233k1();
    }

    static TlsSupportedGroup sect233r1() {
        return NamedCurve.sect233r1();
    }

    static TlsSupportedGroup sect239k1() {
        return NamedCurve.sect239k1();
    }

    static TlsSupportedGroup sect283k1() {
        return NamedCurve.sect283k1();
    }

    static TlsSupportedGroup sect283r1() {
        return NamedCurve.sect283r1();
    }

    static TlsSupportedGroup sect409k1() {
        return NamedCurve.sect409k1();
    }

    static TlsSupportedGroup sect409r1() {
        return NamedCurve.sect409r1();
    }

    static TlsSupportedGroup sect571k1() {
        return NamedCurve.sect571k1();
    }

    static TlsSupportedGroup sect571r1() {
        return NamedCurve.sect571r1();
    }

    static TlsSupportedGroup secp160k1() {
        return NamedCurve.secp160k1();
    }

    static TlsSupportedGroup secp160r1() {
        return NamedCurve.secp160r1();
    }

    static TlsSupportedGroup secp160r2() {
        return NamedCurve.secp160r2();
    }

    static TlsSupportedGroup secp192k1() {
        return NamedCurve.secp192k1();
    }

    static TlsSupportedGroup secp192r1() {
        return NamedCurve.secp192r1();
    }

    static TlsSupportedGroup secp224k1() {
        return NamedCurve.secp224k1();
    }

    static TlsSupportedGroup secp224r1() {
        return NamedCurve.secp224r1();
    }

    static TlsSupportedGroup secp256k1() {
        return NamedCurve.secp256k1();
    }

    static TlsSupportedGroup secp256r1() {
        return NamedCurve.secp256r1();
    }

    static TlsSupportedGroup secp384r1() {
        return NamedCurve.secp384r1();
    }

    static TlsSupportedGroup secp521r1() {
        return NamedCurve.secp521r1();
    }

    static TlsSupportedGroup brainpoolp256r1() {
        return NamedCurve.brainpoolp256r1();
    }

    static TlsSupportedGroup brainpoolp384r1() {
        return NamedCurve.brainpoolp384r1();
    }

    static TlsSupportedGroup brainpoolp512r1() {
        return NamedCurve.brainpoolp512r1();
    }

    static TlsSupportedGroup gc256a() {
        return NamedCurve.gc256a();
    }

    static TlsSupportedGroup gc256b() {
        return NamedCurve.gc256b();
    }

    static TlsSupportedGroup gc256c() {
        return NamedCurve.gc256c();
    }

    static TlsSupportedGroup gc256d() {
        return NamedCurve.gc256d();
    }

    static TlsSupportedGroup gc512a() {
        return NamedCurve.gc512a();
    }

    static TlsSupportedGroup gc512b() {
        return NamedCurve.gc512b();
    }

    static TlsSupportedGroup gc512c() {
        return NamedCurve.gc512c();
    }

    static TlsSupportedGroup x25519() {
        return NamedCurve.x25519();
    }

    static TlsSupportedGroup x448() {
        return NamedCurve.x448();
    }

    static TlsSupportedGroup mlKem512() {
        return NamedCurve.mlKem512();
    }

    static TlsSupportedGroup mlKem768() {
        return NamedCurve.mlKem768();
    }

    static TlsSupportedGroup mlKem1024() {
        return NamedCurve.mlKem1024();
    }

    static TlsSupportedGroup ffdhe2048() {
        return NamedCurve.ffdhe2048();
    }

    static TlsSupportedGroup ffdhe3072() {
        return NamedCurve.ffdhe3072();
    }

    static TlsSupportedGroup ffdhe4096() {
        return NamedCurve.ffdhe4096();
    }

    static TlsSupportedGroup ffdhe6144() {
        return NamedCurve.ffdhe6144();
    }

    static TlsSupportedGroup ffdhe8192() {
        return NamedCurve.ffdhe8192();
    }

    static TlsSupportedGroup x25519MlKem768() {
        return NamedCurve.x25519MlKem768();
    }

    static TlsSupportedGroup secp256r1MlKem768() {
        return NamedCurve.secp256r1MlKem768();
    }

    static TlsSupportedGroup brainpoolp256r1Tls13() {
        return NamedCurve.brainpoolp256r1Tls13();
    }

    static TlsSupportedGroup brainpoolp384r1Tls13() {
        return NamedCurve.brainpoolp384r1Tls13();
    }

    static TlsSupportedGroup brainpoolp512r1Tls13() {
        return NamedCurve.brainpoolp512r1Tls13();
    }

    static TlsSupportedGroup explicitPrime(TlsECParameters parameters) {
        if(!(parameters instanceof ExplicitPrimeParameters primeParameters)) {
            throw new TlsException("Parameters mismatch");
        }

        return new ExplicitPrime(primeParameters);
    }

    static TlsSupportedGroup explicitChar2(TlsECParameters parameters) {
        if(!(parameters instanceof ExplicitChar2Parameters char2Parameters)) {
            throw new TlsException("Parameters mismatch");
        }

        return new ExplicitChar2(char2Parameters);
    }

    int id();
    boolean dtls();
    KeyPair generateLocalKeyPair(TlsContext context);
    byte[] dumpLocalPublicKey(TlsContext context);
    PublicKey parseRemotePublicKey(TlsContext context);
    byte[] computeSharedSecret(TlsContext context);
    Optional<TlsECParameters> toEllipticCurveParameters();
    Optional<TlsECParametersDeserializer> ellipticCurveParametersDeserializer();
}
