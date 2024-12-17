package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.concrete.ClientSupportedVersionsExtension;
import it.auties.leap.tls.extension.concrete.GreaseExtension;

import java.util.List;
import java.util.Optional;

public final class ClientSupportedVersionsModel extends TlsExtension.Model<ClientSupportedVersionsModel, ClientSupportedVersionsModel.Config, ClientSupportedVersionsExtension> {
    public static final ClientSupportedVersionsModel INSTANCE = new ClientSupportedVersionsModel();
    private ClientSupportedVersionsModel() {

    }

    @Override
    public Optional<ClientSupportedVersionsExtension> create(Config config) {
        if(config.tlsVersions().isEmpty()) {
            return Optional.empty();
        }

        var result = new ClientSupportedVersionsExtension(config.tlsVersions());
        return Optional.of(result);
    }

    @Override
    public Class<ClientSupportedVersionsExtension> resultType() {
        return ClientSupportedVersionsExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.some(GreaseExtension.class, ClientSupportedVersionsExtension.class);
    }

    public record Config(List<TlsVersionId> tlsVersions) implements Model.Config<ClientSupportedVersionsModel> {

    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
