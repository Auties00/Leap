package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.TlsVersion;
import it.auties.leap.tls.extension.TlsModelExtension;
import it.auties.leap.tls.extension.concrete.SNIExtension;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public final class SNIExtensionModel extends TlsModelExtension<SNIExtensionModel.Config, SNIExtension> {
    public static final SNIExtensionModel INSTANCE = new SNIExtensionModel();
    private SNIExtensionModel() {

    }

    @Override
    public Optional<SNIExtension> create(Config config) {
        if(!config.type().isValid(config.name())) {
            return Optional.empty();
        }

        var result = new SNIExtension(config.name().getBytes(StandardCharsets.US_ASCII), config.type());
        return Optional.of(result);
    }

    public record Config(String name, SNIExtension.NameType type) implements TlsModelExtension.Config {

    }

    @Override
    public Class<SNIExtension> resultType() {
        return SNIExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12, TlsVersion.TLS13);
    }
}
