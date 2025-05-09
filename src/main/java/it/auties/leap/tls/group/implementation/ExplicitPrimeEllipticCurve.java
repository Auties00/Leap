package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsEcCurveType;
import it.auties.leap.tls.ec.TlsEcParametersDeserializer;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.connection.TlsConnectionSecret;

import java.security.KeyPair;
import java.security.PublicKey;

public final class ExplicitPrimeEllipticCurve implements TlsSupportedEllipticCurve {
    private final TlsEcCurveType.ExplicitPrime parameters;

    public ExplicitPrimeEllipticCurve(TlsEcCurveType.ExplicitPrime parameters) {
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
    public TlsEcCurveType toParameters() {
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
    public TlsConnectionSecret computeSharedSecret(TlsContext context) {
        throw new UnsupportedOperationException();
    }
}
