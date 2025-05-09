package it.auties.leap.tls.ec;

import java.nio.ByteBuffer;

public interface TlsEcParametersDeserializer {
    static TlsEcParametersDeserializer explicitChar2() {
        return TlsEcCurveType.ExplicitChar2.DESERIALIZER;
    }

    static TlsEcParametersDeserializer explicitPrime() {
        return TlsEcCurveType.ExplicitPrime.DESERIALIZER;
    }

    static TlsEcParametersDeserializer namedCurve() {
        return TlsEcCurveType.NamedCurve.DESERIALIZER;
    }

    byte id();
    TlsEcCurveType deserialize(ByteBuffer buffer);
}
