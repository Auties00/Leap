package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.ec.TlsEcParameters;
import it.auties.leap.tls.ec.TlsEcParametersDeserializer;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class NamedCurveParameters implements TlsEcParameters {
    private static final TlsEcParametersDeserializer DESERIALIZER = new TlsEcParametersDeserializer() {
        @Override
        public byte type() {
            return 3;
        }

        @Override
        public TlsEcParameters deserialize(ByteBuffer input) {
            var namedGroup = readBigEndianInt16(input);
            return new NamedCurveParameters(namedGroup);
        }
    };

    private final int namedGroup;

    public NamedCurveParameters(int namedGroup) {
        this.namedGroup = namedGroup;
    }

    public static TlsEcParametersDeserializer deserializer() {
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
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: " + TlsProperty.supportedGroups().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .filter(entry -> entry instanceof TlsSupportedEllipticCurve supportedCurve && supportedCurve.accepts(namedGroup))
                .findFirst()
                .map(entry -> (TlsSupportedEllipticCurve) entry)
                .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
    }
}
