package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;

import java.util.Optional;

non-sealed public interface TlsConfigurableExtension extends TlsExtension {
    Optional<? extends TlsConcreteExtension> newInstance(TlsContext context, int messageLength);

    TlsExtensionDependencies dependencies();
}
