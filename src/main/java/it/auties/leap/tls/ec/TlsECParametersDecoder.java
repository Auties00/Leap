package it.auties.leap.tls.ec;

import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;

import java.nio.ByteBuffer;

public interface TlsECParametersDecoder {
    byte id();
    TlsECParameters decode(ByteBuffer buffer);

    static TlsECParametersDecoder explicitChar2() {
        return ExplicitChar2Parameters.parametersDecoder();
    }

    static TlsECParametersDecoder explicitPrime() {
        return ExplicitPrimeParameters.parametersDecoder();
    }

    static TlsECParametersDecoder namedCurve() {
        return NamedCurveParameters.parametersDecoder();
    }
}
