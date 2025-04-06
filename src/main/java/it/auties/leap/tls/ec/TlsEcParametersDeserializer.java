package it.auties.leap.tls.ec;

import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;

import java.nio.ByteBuffer;

public interface TlsEcParametersDeserializer {
    byte type();
    TlsEcParameters deserialize(ByteBuffer buffer);
    default boolean accepts(byte ecType) {
        return ecType == type();
    }

    static TlsEcParametersDeserializer explicitChar2() {
        return ExplicitChar2Parameters.deserializer();
    }

    static TlsEcParametersDeserializer explicitPrime() {
        return ExplicitPrimeParameters.deserializer();
    }

    static TlsEcParametersDeserializer namedCurve() {
        return NamedCurveParameters.deserializer();
    }
}
