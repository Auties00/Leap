package it.auties.leap.tls.extension.implementation.sni;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsConfigurableClientExtension;
import it.auties.leap.tls.extension.TlsConfigurableServerExtension;
import it.auties.leap.tls.extension.TlsConfiguredExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.name.TlsNameType;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

public record SNIConfigurableExtension(
        TlsNameType nameType
) implements TlsConfigurableClientExtension, TlsConfigurableServerExtension {
    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    @Override
    public Optional<? extends TlsConfiguredExtension> configure(TlsContext context, int messageLength) {
        return switch (nameType) {
            case HOST_NAME -> {
                var hostname = context.address()
                        .map(InetSocketAddress::getHostName)
                        .orElse(null);
                if(hostname == null || !nameType.accepts(hostname)) {
                    yield Optional.empty();
                }

                var name = hostname.getBytes(StandardCharsets.US_ASCII);
                yield Optional.of(new SNIExtension(name, nameType));
            }
        };
    }

    @Override
    public int extensionType() {
        return SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SERVER_NAME_VERSIONS;
    }
}
