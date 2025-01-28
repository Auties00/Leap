package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDecoder;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class NamedCurveParameters implements TlsECParameters {
    private static final TlsECParametersDecoder DECODER = input -> {
        var namedGroup = readLittleEndianInt16(input);
        return new NamedCurveParameters(namedGroup);
    };

    private final int namedGroup;

    public NamedCurveParameters(int namedGroup) {
        this.namedGroup = namedGroup;
    }

    public static TlsECParametersDecoder decoder() {
        return DECODER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeLittleEndianInt16(buffer, namedGroup);
    }

    @Override
    public int length() {
        return INT16_LENGTH;
    }
}
