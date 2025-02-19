package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.psk.TlsPSKExchangeMode;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record PSKExchangeModesExtension(
        List<Byte> modes
) implements TlsExtension.Concrete {
    private static final TlsExtensionDeserializer DECODER = new TlsExtensionDeserializer(){
        @Override
        public Optional<? extends Concrete> deserialize(ByteBuffer buffer, int type, TlsMode mode) {
            var modesSize = readBigEndianInt16(buffer);
            var modes = new ArrayList<Byte>(modesSize);
            for(var i = 0; i < modesSize; i++) {
                var modeId = readBigEndianInt8(buffer);
                modes.add(modeId);
            }
            var extension = new PSKExchangeModesExtension(modes);
            return Optional.of(extension);
        }

        @Override
        public Class<? extends Concrete> toConcreteType(TlsMode mode) {
            return PSKExchangeModesExtension.class;
        }
    };

    public static PSKExchangeModesExtension of(List<TlsPSKExchangeMode> modes) {
        return new PSKExchangeModesExtension(modes.stream()
                .map(TlsPSKExchangeMode::id)
                .toList());
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, modes.size());
        for (var mode : modes) {
            writeBigEndianInt8(buffer, mode);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + INT8_LENGTH * modes.size();
    }

    @Override
    public int extensionType() {
        return PSK_KEY_EXCHANGE_MODES_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return PSK_KEY_EXCHANGE_MODES_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer decoder() {
        return DECODER;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (PSKExchangeModesExtension) obj;
        return Objects.equals(this.modes, that.modes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(modes);
    }

    @Override
    public String toString() {
        return "PSKExchangeModesExtension[" +
                "modes=" + modes + ']';
    }
}
