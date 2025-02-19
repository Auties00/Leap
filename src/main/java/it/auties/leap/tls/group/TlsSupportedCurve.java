package it.auties.leap.tls.group;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.group.implementation.ExplicitChar2Curve;
import it.auties.leap.tls.group.implementation.ExplicitPrimeCurve;
import it.auties.leap.tls.group.implementation.NamedCurve;

public non-sealed interface TlsSupportedCurve extends TlsSupportedGroup {
    static TlsSupportedCurve sect163k1() {
        return NamedCurve.sect163k1();
    }

    static TlsSupportedCurve sect163r1() {
        return NamedCurve.sect163r1();
    }

    static TlsSupportedCurve sect163r2() {
        return NamedCurve.sect163r2();
    }

    static TlsSupportedCurve sect193r1() {
        return NamedCurve.sect193r1();
    }

    static TlsSupportedCurve sect193r2() {
        return NamedCurve.sect193r2();
    }

    static TlsSupportedCurve sect233k1() {
        return NamedCurve.sect233k1();
    }

    static TlsSupportedCurve sect233r1() {
        return NamedCurve.sect233r1();
    }

    static TlsSupportedCurve sect239k1() {
        return NamedCurve.sect239k1();
    }

    static TlsSupportedCurve sect283k1() {
        return NamedCurve.sect283k1();
    }

    static TlsSupportedCurve sect283r1() {
        return NamedCurve.sect283r1();
    }

    static TlsSupportedCurve sect409k1() {
        return NamedCurve.sect409k1();
    }

    static TlsSupportedCurve sect409r1() {
        return NamedCurve.sect409r1();
    }

    static TlsSupportedCurve sect571k1() {
        return NamedCurve.sect571k1();
    }

    static TlsSupportedCurve sect571r1() {
        return NamedCurve.sect571r1();
    }

    static TlsSupportedCurve secp160k1() {
        return NamedCurve.secp160k1();
    }

    static TlsSupportedCurve secp160r1() {
        return NamedCurve.secp160r1();
    }

    static TlsSupportedCurve secp160r2() {
        return NamedCurve.secp160r2();
    }

    static TlsSupportedCurve secp192k1() {
        return NamedCurve.secp192k1();
    }

    static TlsSupportedCurve secp192r1() {
        return NamedCurve.secp192r1();
    }

    static TlsSupportedCurve secp224k1() {
        return NamedCurve.secp224k1();
    }

    static TlsSupportedCurve secp224r1() {
        return NamedCurve.secp224r1();
    }

    static TlsSupportedCurve secp256k1() {
        return NamedCurve.secp256k1();
    }

    static TlsSupportedCurve secp256r1() {
        return NamedCurve.secp256r1();
    }

    static TlsSupportedCurve secp384r1() {
        return NamedCurve.secp384r1();
    }

    static TlsSupportedCurve secp521r1() {
        return NamedCurve.secp521r1();
    }

    static TlsSupportedCurve brainpoolp256r1() {
        return NamedCurve.brainpoolp256r1();
    }

    static TlsSupportedCurve brainpoolp384r1() {
        return NamedCurve.brainpoolp384r1();
    }

    static TlsSupportedCurve brainpoolp512r1() {
        return NamedCurve.brainpoolp512r1();
    }

    static TlsSupportedCurve gc256a() {
        return NamedCurve.gc256a();
    }

    static TlsSupportedCurve gc256b() {
        return NamedCurve.gc256b();
    }

    static TlsSupportedCurve gc256c() {
        return NamedCurve.gc256c();
    }

    static TlsSupportedCurve gc256d() {
        return NamedCurve.gc256d();
    }

    static TlsSupportedCurve gc512a() {
        return NamedCurve.gc512a();
    }

    static TlsSupportedCurve gc512b() {
        return NamedCurve.gc512b();
    }

    static TlsSupportedCurve gc512c() {
        return NamedCurve.gc512c();
    }

    static TlsSupportedCurve x25519() {
        return NamedCurve.x25519();
    }

    static TlsSupportedCurve x448() {
        return NamedCurve.x448();
    }

    static TlsSupportedCurve mlKem512() {
        return NamedCurve.mlKem512();
    }

    static TlsSupportedCurve mlKem768() {
        return NamedCurve.mlKem768();
    }

    static TlsSupportedCurve mlKem1024() {
        return NamedCurve.mlKem1024();
    }

    static TlsSupportedCurve x25519MlKem768() {
        return NamedCurve.x25519MlKem768();
    }

    static TlsSupportedCurve secp256r1MlKem768() {
        return NamedCurve.secp256r1MlKem768();
    }

    static TlsSupportedCurve brainpoolp256r1Tls13() {
        return NamedCurve.brainpoolp256r1Tls13();
    }

    static TlsSupportedCurve brainpoolp384r1Tls13() {
        return NamedCurve.brainpoolp384r1Tls13();
    }

    static TlsSupportedCurve brainpoolp512r1Tls13() {
        return NamedCurve.brainpoolp512r1Tls13();
    }

    static TlsSupportedCurve explicitPrime(TlsECParameters parameters) {
        if (!(parameters instanceof ExplicitPrimeParameters primeParameters)) {
            throw new TlsException("Parameters mismatch");
        }

        return new ExplicitPrimeCurve(primeParameters);
    }

    static TlsSupportedCurve explicitChar2(TlsECParameters parameters) {
        if (!(parameters instanceof ExplicitChar2Parameters char2Parameters)) {
            throw new TlsException("Parameters mismatch");
        }

        return new ExplicitChar2Curve(char2Parameters);
    }

    byte[] dumpLocalPublicKey(TlsContext context);

    TlsECParameters toParameters();

    TlsECParametersDeserializer parametersDeserializer();
}
