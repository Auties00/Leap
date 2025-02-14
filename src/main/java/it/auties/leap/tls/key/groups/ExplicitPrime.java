package it.auties.leap.tls.key.groups;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Optional;

public final class ExplicitPrime implements TlsSupportedGroup {
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
    public Optional<TlsECParameters> toEllipticCurveParameters() {
        return Optional.of(parameters);
    }

    @Override
    public Optional<TlsECParametersDeserializer> ellipticCurveParametersDeserializer() {
        return Optional.of(TlsECParametersDeserializer.explicitPrime());
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
    public PublicKey parseRemotePublicKey(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] computeSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
