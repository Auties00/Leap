package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;

import java.nio.ByteBuffer;

public final class UnsupportedParameters implements TlsECParametersDecoder {
    private static final UnsupportedParameters INSTANCE = new UnsupportedParameters();
    private UnsupportedParameters() {

    }

    public static UnsupportedParameters instance() {
        return INSTANCE;
    }

    @Override
    public TlsECParameters decodeParameters(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }
}
