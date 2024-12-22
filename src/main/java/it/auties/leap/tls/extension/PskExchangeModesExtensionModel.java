package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

final class PskExchangeModesExtensionModel implements TlsExtension.Model{
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
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
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return PskExchangeModesExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.PSK_KEY_EXCHANGE_MODES_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.PSK_KEY_EXCHANGE_MODES_VERSIONS;
    }
}
