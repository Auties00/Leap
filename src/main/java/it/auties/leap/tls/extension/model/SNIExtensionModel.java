package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.concrete.SNIExtension;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public final class SNIExtensionModel implements TlsExtension.Model<SNIExtension> {
    public static final SNIExtensionModel INSTANCE = new SNIExtensionModel();
    private SNIExtensionModel() {

    }

    @Override
    public Optional<SNIExtension> create(Context context) {
        var hostname = context.address().getHostName();
        var type = SNIExtension.NameType.HOST_NAME;
        if(!type.isValid(hostname)) {
            return Optional.empty();
        }

        var result = new SNIExtension(hostname.getBytes(StandardCharsets.US_ASCII), type);
        return Optional.of(result);
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
