package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferHelper.INT8_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.writeLittleEndianInt8;

public final class PskExchangeModesExtension implements TlsExtension.Implementation {
    private final List<Byte> modes;
    PskExchangeModesExtension(List<Byte> modes) {
        this.modes = modes;
    }

    @Override
    public void serializeExtensionPayload(ByteBuffer buffer) {
        writeLittleEndianInt8(buffer, modes.size());
        for (var mode : modes) {
            writeLittleEndianInt8(buffer, mode);
        }
    }

    @Override
    public int extensionPayloadLength() {
        return INT8_LENGTH + modes.size();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.PSK_KEY_EXCHANGE_MODES_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.PSK_KEY_EXCHANGE_MODES_VERSIONS;
    }

    public List<Byte> modes() {
        return modes;
    }

}
