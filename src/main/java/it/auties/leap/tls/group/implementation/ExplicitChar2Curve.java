package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.group.TlsSupportedCurve;

import java.security.KeyPair;

public final class ExplicitChar2Curve implements TlsSupportedCurve {
    private final ExplicitChar2Parameters parameters;

    public ExplicitChar2Curve(ExplicitChar2Parameters parameters) {
        this.parameters = parameters;
    }

    @Override
    public Integer id() {
        return 65282;
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
        return TlsECParametersDeserializer.explicitChar2();
    }

    @Override
    public KeyPair generateLocalKeyPair(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] dumpPublicKey(KeyPair keyPair) {
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
