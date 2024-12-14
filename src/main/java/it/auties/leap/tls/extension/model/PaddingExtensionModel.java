package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsModelExtension;
import it.auties.leap.tls.extension.concrete.PaddingExtension;

import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.TlsBuffer.INT16_LENGTH;

public final class PaddingExtensionModel extends TlsModelExtension<PaddingExtensionModel.Config, PaddingExtension> {
    private final int targetLength;
    public PaddingExtensionModel(int targetLength) {
        this.targetLength = targetLength;
    }

    @Override
    public Optional<PaddingExtension> create(Config config) {
        var actualLength = config.actualLength() + INT16_LENGTH + INT16_LENGTH;
        if(config.actualLength() > targetLength) {
            return Optional.empty();
        }

        var result = new PaddingExtension(targetLength - actualLength);
        return Optional.of(result);
    }

    public record Config(int actualLength) implements TlsModelExtension.Config {

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
