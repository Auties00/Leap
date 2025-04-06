package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsEcParameters;
import it.auties.leap.tls.ec.TlsEcParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.secret.TlsSecret;

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
    public TlsEcParameters toParameters() {
        return parameters;
    }

    @Override
    public TlsEcParametersDeserializer parametersDeserializer() {
        return TlsEcParametersDeserializer.explicitPrime();
    }

    @Override
    public KeyPair generateKeyPair(TlsContext context) {
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
    public PublicKey parsePublicKey(byte[] rawPublicKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsSecret computeSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
