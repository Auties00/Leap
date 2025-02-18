package it.auties.leap.tls.ec;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.key.TlsSupportedCurve;

import java.nio.ByteBuffer;

// https://github.com/topskychen/spongycastle/blob/master/core/src/main/java/org/bouncycastle/crypto/tls/TlsECCUtils.java#L420
public interface TlsECParameters {
    void serialize(ByteBuffer buffer);
    int length();
    TlsSupportedCurve toGroup(TlsContext context);

    static TlsECParameters explicitChar2(int m, byte basis, int k, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2Parameters(m, basis, k, a, b, encoding, order, cofactor);
    }

    static TlsECParameters explicitChar2(int m, byte basis, int k1, int k2, int k3, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitChar2Parameters(m, basis, k1, k2, k3, a, b, encoding, order, cofactor);
    }

    static TlsECParameters explicitPrime(byte[] prime, byte[] a, byte[] b, byte[] encoding, byte[] order, byte[] cofactor) {
        return new ExplicitPrimeParameters(prime, a, b, encoding, order, cofactor);
    }

    static TlsECParameters namedCurve(int id) {
        return new NamedCurveParameters(id);
    }
}
