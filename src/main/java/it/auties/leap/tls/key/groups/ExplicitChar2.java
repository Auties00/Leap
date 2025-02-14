package it.auties.leap.tls.key.groups;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.key.TlsSupportedGroup;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Optional;

public final class ExplicitChar2 implements TlsSupportedGroup {
    private final ExplicitChar2Parameters parameters;

    public ExplicitChar2(ExplicitChar2Parameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public int id() {
        return 65282;
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
        return Optional.of(TlsECParametersDeserializer.explicitChar2());
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
