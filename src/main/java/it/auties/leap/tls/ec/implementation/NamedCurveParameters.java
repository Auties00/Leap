package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.group.TlsSupportedCurve;

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
    public TlsSupportedCurve toGroup(TlsContext context) {
        return context.localSupportedGroups()
                .stream()
                .filter(entry -> entry instanceof TlsSupportedCurve supportedCurve && supportedCurve.accepts(namedGroup))
                .findFirst()
                .map(entry -> (TlsSupportedCurve) entry)
                .orElseThrow(() -> new TlsException("No supported group matches the id " + namedGroup));
    }
}
