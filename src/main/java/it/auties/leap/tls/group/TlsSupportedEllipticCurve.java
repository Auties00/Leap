package it.auties.leap.tls.group;

import it.auties.leap.tls.ec.TlsEcCurveType;
import it.auties.leap.tls.ec.TlsEcParametersDeserializer;
import it.auties.leap.tls.group.implementation.ExplicitChar2EllipticCurve;
import it.auties.leap.tls.group.implementation.ExplicitPrimeEllipticCurve;
import it.auties.leap.tls.group.implementation.NamedEllipticCurve;

public non-sealed interface TlsSupportedEllipticCurve extends TlsSupportedGroup {
    static TlsSupportedEllipticCurve sect163k1() {
        return NamedEllipticCurve.sect163k1();
    }

    static TlsSupportedEllipticCurve sect163r1() {
        return NamedEllipticCurve.sect163r1();
    }

    static TlsSupportedEllipticCurve sect163r2() {
        return NamedEllipticCurve.sect163r2();
    }

    static TlsSupportedEllipticCurve sect193r1() {
        return NamedEllipticCurve.sect193r1();
    }

    static TlsSupportedEllipticCurve sect193r2() {
        return NamedEllipticCurve.sect193r2();
    }

    static TlsSupportedEllipticCurve sect233k1() {
        return NamedEllipticCurve.sect233k1();
    }

    static TlsSupportedEllipticCurve sect233r1() {
        return NamedEllipticCurve.sect233r1();
    }

    static TlsSupportedEllipticCurve sect239k1() {
        return NamedEllipticCurve.sect239k1();
    }

    static TlsSupportedEllipticCurve sect283k1() {
        return NamedEllipticCurve.sect283k1();
    }

    static TlsSupportedEllipticCurve sect283r1() {
        return NamedEllipticCurve.sect283r1();
    }

    static TlsSupportedEllipticCurve sect409k1() {
        return NamedEllipticCurve.sect409k1();
    }

    static TlsSupportedEllipticCurve sect409r1() {
        return NamedEllipticCurve.sect409r1();
    }

    static TlsSupportedEllipticCurve sect571k1() {
        return NamedEllipticCurve.sect571k1();
    }

    static TlsSupportedEllipticCurve sect571r1() {
        return NamedEllipticCurve.sect571r1();
    }

    static TlsSupportedEllipticCurve secp160k1() {
        return NamedEllipticCurve.secp160k1();
    }

    static TlsSupportedEllipticCurve secp160r1() {
        return NamedEllipticCurve.secp160r1();
    }

    static TlsSupportedEllipticCurve secp160r2() {
        return NamedEllipticCurve.secp160r2();
    }

    static TlsSupportedEllipticCurve secp192k1() {
        return NamedEllipticCurve.secp192k1();
    }

    static TlsSupportedEllipticCurve secp192r1() {
        return NamedEllipticCurve.secp192r1();
    }

    static TlsSupportedEllipticCurve secp224k1() {
        return NamedEllipticCurve.secp224k1();
    }

    static TlsSupportedEllipticCurve secp224r1() {
        return NamedEllipticCurve.secp224r1();
    }

    static TlsSupportedEllipticCurve secp256k1() {
        return NamedEllipticCurve.secp256k1();
    }

    static TlsSupportedEllipticCurve secp256r1() {
        return NamedEllipticCurve.secp256r1();
    }

    static TlsSupportedEllipticCurve secp384r1() {
        return NamedEllipticCurve.secp384r1();
    }

    static TlsSupportedEllipticCurve secp521r1() {
        return NamedEllipticCurve.secp521r1();
    }

    static TlsSupportedEllipticCurve brainpoolp256r1() {
        return NamedEllipticCurve.brainpoolp256r1();
    }

    static TlsSupportedEllipticCurve brainpoolp384r1() {
        return NamedEllipticCurve.brainpoolp384r1();
    }

    static TlsSupportedEllipticCurve brainpoolp512r1() {
        return NamedEllipticCurve.brainpoolp512r1();
    }

    static TlsSupportedEllipticCurve gc256a() {
        return NamedEllipticCurve.gc256a();
    }

    static TlsSupportedEllipticCurve gc256b() {
        return NamedEllipticCurve.gc256b();
    }

    static TlsSupportedEllipticCurve gc256c() {
        return NamedEllipticCurve.gc256c();
    }

    static TlsSupportedEllipticCurve gc256d() {
        return NamedEllipticCurve.gc256d();
    }

    static TlsSupportedEllipticCurve gc512a() {
        return NamedEllipticCurve.gc512a();
    }

    static TlsSupportedEllipticCurve gc512b() {
        return NamedEllipticCurve.gc512b();
    }

    static TlsSupportedEllipticCurve gc512c() {
        return NamedEllipticCurve.gc512c();
    }

    static TlsSupportedEllipticCurve x25519() {
        return NamedEllipticCurve.x25519();
    }

    static TlsSupportedEllipticCurve x448() {
        return NamedEllipticCurve.x448();
    }

    static TlsSupportedEllipticCurve mlKem512() {
        return NamedEllipticCurve.mlKem512();
    }

    static TlsSupportedEllipticCurve mlKem768() {
        return NamedEllipticCurve.mlKem768();
    }

    static TlsSupportedEllipticCurve mlKem1024() {
        return NamedEllipticCurve.mlKem1024();
    }

    static TlsSupportedEllipticCurve x25519MlKem768() {
        return NamedEllipticCurve.x25519MlKem768();
    }

    static TlsSupportedEllipticCurve secp256r1MlKem768() {
        return NamedEllipticCurve.secp256r1MlKem768();
    }

    static TlsSupportedEllipticCurve brainpoolp256r1Tls13() {
        return NamedEllipticCurve.brainpoolp256r1Tls13();
    }

    static TlsSupportedEllipticCurve brainpoolp384r1Tls13() {
        return NamedEllipticCurve.brainpoolp384r1Tls13();
    }

    static TlsSupportedEllipticCurve brainpoolp512r1Tls13() {
        return NamedEllipticCurve.brainpoolp512r1Tls13();
    }

    static TlsSupportedEllipticCurve explicitPrime(TlsEcCurveType.ExplicitPrime parameters) {
        return new ExplicitPrimeEllipticCurve(parameters);
    }

    static TlsSupportedEllipticCurve explicitChar2(TlsEcCurveType.ExplicitChar2 parameters) {
        return new ExplicitChar2EllipticCurve(parameters);
    }

    TlsEcCurveType toParameters();

    TlsEcParametersDeserializer parametersDeserializer();

    boolean accepts(int namedGroup);
}
