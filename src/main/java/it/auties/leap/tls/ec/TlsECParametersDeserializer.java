package it.auties.leap.tls.ec;

import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;

import java.nio.ByteBuffer;

public interface TlsECParametersDeserializer {
    byte type();
    TlsECParameters deserialize(ByteBuffer buffer);

    static TlsECParametersDeserializer explicitChar2() {
        return ExplicitChar2Parameters.deserializer();
    }

    static TlsECParametersDeserializer explicitPrime() {
        return ExplicitPrimeParameters.deserializer();
    }

    static TlsECParametersDeserializer namedCurve() {
        return NamedCurveParameters.deserializer();
    }
}
