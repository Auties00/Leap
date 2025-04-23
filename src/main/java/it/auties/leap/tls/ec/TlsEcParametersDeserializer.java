package it.auties.leap.tls.ec;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.nio.ByteBuffer;

public interface TlsEcParametersDeserializer extends TlsIdentifiableProperty<Byte> {
    static TlsEcParametersDeserializer explicitChar2() {
        return TlsEcCurveType.ExplicitChar2.DESERIALIZER;
    }

    static TlsEcParametersDeserializer explicitPrime() {
        return TlsEcCurveType.ExplicitPrime.DESERIALIZER;
    }

    static TlsEcParametersDeserializer namedCurve() {
        return TlsEcCurveType.NamedCurve.DESERIALIZER;
    }

    TlsEcCurveType deserialize(ByteBuffer buffer);
}
