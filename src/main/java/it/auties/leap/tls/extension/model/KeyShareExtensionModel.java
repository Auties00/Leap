package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.concrete.KeyShareExtension;
import it.auties.leap.tls.extension.concrete.SupportedGroupsExtension;

import java.util.List;
import java.util.Optional;

public final class KeyShareExtensionModel implements TlsExtension.Model<KeyShareExtension> {
    public static final KeyShareExtensionModel INSTANCE = new KeyShareExtensionModel();
    private KeyShareExtensionModel() {

    }

    @Override
    public Optional<KeyShareExtension> create(Context context) {
        return Optional.empty(); // Implicit
    }

    @Override
    public Class<KeyShareExtension> resultType() {
        return KeyShareExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.some(SupportedGroupsExtension.class);
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
