package it.auties.leap.tls.extension.model;

import it.auties.leap.tls.config.TlsVersion;
import it.auties.leap.tls.config.TlsVersionId;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.concrete.ClientSupportedVersionsExtension;
import it.auties.leap.tls.extension.concrete.GreaseExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

public final class ClientSupportedVersionsModel implements TlsExtension.Model<ClientSupportedVersionsExtension> {
    public static final ClientSupportedVersionsModel INSTANCE = new ClientSupportedVersionsModel();
    private ClientSupportedVersionsModel() {

    }

    @Override
    public Optional<ClientSupportedVersionsExtension> create(Context context) {
        var supportedVersions = new ArrayList<TlsVersionId>();
        var chosenVersion = context.config().version();
        switch (chosenVersion) {
            case TLS13 -> {
                supportedVersions.add(TlsVersion.TLS13.id());
                supportedVersions.add(TlsVersion.TLS12.id());
            }
            case DTLS13 -> {
                supportedVersions.add(TlsVersion.DTLS13.id());
                supportedVersions.add(TlsVersion.DTLS12.id());
            }
            default -> supportedVersions.add(chosenVersion.id());
        }

        if(context.hasExtension(GreaseExtension::isGrease)) {
            supportedVersions.add(randomGrease());
        }

        var result = new ClientSupportedVersionsExtension(supportedVersions);
        return Optional.of(result);
    }

    private static TlsVersionId randomGrease() {
        var grease = TlsVersionId.grease();
        return grease.get(ThreadLocalRandom.current().nextInt(0, grease.size()));
    }

    @Override
    public Class<ClientSupportedVersionsExtension> resultType() {
        return ClientSupportedVersionsExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.some(GreaseExtension.class);
    }

    @Override
    public List<TlsVersion> versions() {
        return List.of(TlsVersion.TLS13);
    }
}
