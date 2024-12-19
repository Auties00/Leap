package it.auties.leap.tls.extension.concrete;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.*;

public record PskExchangeModesExtension(List<Byte> modes) implements TlsExtension.Concrete {
    public static final int EXTENSION_TYPE = 0x002D;

    public static Optional<PskExchangeModesExtension> of(TlsVersion version, ByteBuffer buffer, int extensionLength) {
        var modesSize = readLittleEndianInt16(buffer);
        var modes = new ArrayList<Byte>(modesSize);
        for(var i = 0; i < modesSize; i++) {
            var modeId = readLittleEndianInt8(buffer);
            modes.add(modeId);
        }
        var extension = new PskExchangeModesExtension(modes);
        return Optional.of(extension);
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, modes.size());
        for(var mode : modes) {
            writeLittleEndianInt8(buffer, mode);
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
