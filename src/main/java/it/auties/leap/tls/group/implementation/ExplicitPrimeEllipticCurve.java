package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;

import java.security.KeyPair;
import java.security.PublicKey;

public final class ExplicitPrimeEllipticCurve implements TlsSupportedEllipticCurve {
    private final ExplicitPrimeParameters parameters;

    public ExplicitPrimeEllipticCurve(ExplicitPrimeParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public Integer id() {
        return 65281;
    }

    @Override
    public boolean dtls() {
        return true;
    }

    @Override
    public TlsECParameters toParameters() {
        return parameters;
    }

    @Override
    public TlsECParametersDeserializer parametersDeserializer() {
        return TlsECParametersDeserializer.explicitPrime();
    }

    @Override
    public KeyPair generateLocalKeyPair(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] dumpPublicKey(PublicKey keyPair) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean accepts(int namedGroup) {
        return false;
    }

    @Override
    public byte[] computeSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
