package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.concrete.PaddingExtension;

import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.BufferHelper.INT16_LENGTH;

public final class PaddingExtensionModel implements TlsExtension.Model<PaddingExtension> {
    private final int targetLength;
    public PaddingExtensionModel(int targetLength) {
        this.targetLength = targetLength;
    }

    @Override
    public Optional<PaddingExtension> create(Context context) {
        var actualLength = context.processedExtensionsLength() + INT16_LENGTH + INT16_LENGTH;
        if(actualLength > targetLength) {
            return Optional.empty();
        }

        var result = new PaddingExtension(targetLength - actualLength);
        return Optional.of(result);
    }

    @Override
    public Class<PaddingExtension> resultType() {
        return PaddingExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.all();
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
