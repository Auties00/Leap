package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.TlsPskKeyExchangeMode;
import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsConcreteExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsBuffer.*;

public final class PskExchangeModesExtension extends TlsConcreteExtension {
    public static final int EXTENSION_TYPE = 0x002D;

    private final List<TlsPskKeyExchangeMode> modes;
    public PskExchangeModesExtension(List<TlsPskKeyExchangeMode> modes) {
       this.modes = modes;
    }

    public static Optional<PskExchangeModesExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var modesSize = readLittleEndianInt16(buffer);
        var modes = new ArrayList<TlsPskKeyExchangeMode>(modesSize);
        for(var i = 0; i < modesSize; i++) {
            var modeId = readLittleEndianInt8(buffer);
            var mode = TlsPskKeyExchangeMode.of(modeId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown tls psk key exchange mode: " + modeId));
            modes.add(mode);
        }
        var extension = new PskExchangeModesExtension(modes);
        return Optional.of(extension);
    }

    @Override
    protected void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, modes.size());
        for(var mode : modes) {
            writeLittleEndianInt8(buffer, mode.id());
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + modes.size();
    }

    @Override
    public int extensionType() {
        return EXTENSION_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
