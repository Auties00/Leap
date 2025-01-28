package it.auties.leap.tls.ec;

import it.auties.leap.tls.ec.implementation.ExplicitChar2Parameters;
import it.auties.leap.tls.ec.implementation.ExplicitPrimeParameters;
import it.auties.leap.tls.ec.implementation.NamedCurveParameters;
import it.auties.leap.tls.ec.implementation.UnsupportedParameters;

import java.nio.ByteBuffer;

public interface TlsECParametersDecoder {
    TlsECParameters decodeParameters(ByteBuffer buffer);

    static TlsECParametersDecoder unsupported() {
        return UnsupportedParameters.instance();
    }

    static TlsECParametersDecoder explicitChar2() {
        return ExplicitChar2Parameters.decoder();
    }

    static TlsECParametersDecoder explicitPrime() {
        return ExplicitPrimeParameters.decoder();
    }

    static TlsECParametersDecoder namedCurve() {
        return NamedCurveParameters.decoder();
    }
}
