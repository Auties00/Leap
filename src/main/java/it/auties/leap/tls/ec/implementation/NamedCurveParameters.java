package it.auties.leap.tls.ec.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.ec.TlsECParametersDeserializer;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.key.TlsSupportedGroup;

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
            var namedGroup = readLittleEndianInt16(input);
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
        writeLittleEndianInt16(buffer, namedGroup);
    }

    @Override
    public int length() {
        return INT16_LENGTH;
    }

    @Override
    public TlsSupportedGroup toGroup(TlsContext context) {
        return context.supportedGroups()
                .stream()
                .filter(entry -> entry.id() == namedGroup)
                .findFirst()
                .orElseThrow(() -> new TlsException("No supported group matches the id " + namedGroup));
    }
}
