package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsPskKeyExchangeMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public final class PskExchangeModesExtension extends TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x002D;

    private final List<? extends TlsIdentifiableUnion<TlsPskKeyExchangeMode, Byte>> modes;
    public PskExchangeModesExtension(List<? extends TlsIdentifiableUnion<TlsPskKeyExchangeMode, Byte>> modes) {
       this.modes = modes;
    }

    public static Optional<PskExchangeModesExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var modesSize = readLittleEndianInt16(buffer);
        var modes = new ArrayList<TlsIdentifiableUnion<TlsPskKeyExchangeMode, Byte>>(modesSize);
        for(var i = 0; i < modesSize; i++) {
            var modeId = readLittleEndianInt8(buffer);
            modes.add(TlsIdentifiableUnion.of(modeId));
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
