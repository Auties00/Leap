package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsEcCurveType;
import it.auties.leap.tls.ec.TlsEcParametersDeserializer;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.secret.TlsSecret;

import java.security.KeyPair;
import java.security.PublicKey;

public final class ExplicitChar2EllipticCurve implements TlsSupportedEllipticCurve {
    private final TlsEcCurveType.ExplicitChar2 parameters;

    public ExplicitChar2EllipticCurve(TlsEcCurveType.ExplicitChar2 parameters) {
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
    public TlsEcCurveType toParameters() {
        return parameters;
    }

    @Override
    public TlsEcParametersDeserializer parametersDeserializer() {
        return TlsEcParametersDeserializer.explicitChar2();
    }

    @Override
    public KeyPair generateKeyPair(TlsContext context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] dumpPublicKey(PublicKey publicKey) {
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
