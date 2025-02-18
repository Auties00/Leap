package it.auties.leap.tls.key.group;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.key.TlsSupportedCurve;

import java.security.KeyPair;

public final class ExplicitPrime implements TlsSupportedCurve {
    private final ExplicitPrimeParameters parameters;

    public ExplicitPrime(ExplicitPrimeParameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public int id() {
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
    public byte[] dumpLocalPublicKey(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] computeSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
