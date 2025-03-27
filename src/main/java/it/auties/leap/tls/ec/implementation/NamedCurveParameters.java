package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class NamedCurveParameters implements TlsECParameters {
    private static final TlsECParametersDeserializer DESERIALIZER = new TlsECParametersDeserializer() {
        @Override
        public byte type() {
            return 3;
        }

        @Override
        public TlsECParameters deserialize(ByteBuffer input) {
            var namedGroup = readBigEndianInt16(input);
            return new NamedCurveParameters(namedGroup);
        }
    };

    private final int namedGroup;

    public NamedCurveParameters(int namedGroup) {
        this.namedGroup = namedGroup;
    }

    public static TlsECParametersDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, namedGroup);
    }

    @Override
    public int length() {
        return INT16_LENGTH;
    }

    @Override
    public TlsSupportedEllipticCurve toGroup(TlsContext context) {
        return context.getNegotiatedValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                .stream()
                .filter(entry -> entry instanceof TlsSupportedEllipticCurve supportedCurve && supportedCurve.accepts(namedGroup))
                .findFirst()
                .map(entry -> (TlsSupportedEllipticCurve) entry)
                .orElseThrow(TlsAlert::noSupportedEllipticCurve);
    }
}
