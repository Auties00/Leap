package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferHelper.readLittleEndianInt8;

final class PaddingExtensionModel implements TlsExtension.Model {
    private final int targetLength;
    PaddingExtensionModel(int targetLength) {
        this.targetLength = targetLength;
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(Context context) {
        var actualLength = context.processedExtensionsLength() + INT16_LENGTH + INT16_LENGTH;
        if(actualLength > targetLength) {
            return Optional.empty();
        }

        var result = new PaddingExtension(targetLength - actualLength);
        return Optional.of(result);
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        var padding = readLittleEndianInt8(buffer);
        var extension = new PaddingExtension(padding);
        return Optional.of(extension);
    }

    @Override
    public Class<? extends TlsExtension.Implementation> toConcreteType(TlsMode mode) {
        return PaddingExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.all();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.PADDING_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.PADDING_VERSIONS;
    }
}
