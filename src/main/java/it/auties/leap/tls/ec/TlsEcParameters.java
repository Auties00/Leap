package it.auties.leap.tls.ec;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.property.TlsSerializableProperty;

// https://github.com/topskychen/spongycastle/blob/master/core/src/main/java/org/bouncycastle/crypto/tls/TlsECCUtils.java#L420
public interface TlsEcParameters extends TlsSerializableProperty {
    TlsSupportedEllipticCurve toGroup(TlsContext context);

    static TlsEcParameters explicitChar2(int m, byte basis, int k, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2Parameters(m, basis, k, a, b, encoding, order, cofactor);
    }

    static TlsEcParameters explicitChar2(int m, byte basis, int k1, int k2, int k3, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2Parameters(m, basis, k1, k2, k3, a, b, encoding, order, cofactor);
    }

    static TlsEcParameters explicitPrime(byte[] prime, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitPrimeParameters(prime, a, b, encoding, order, cofactor);
    }

    static TlsEcParameters namedCurve(int id) {
        return new NamedCurveParameters(id);
    }
}
