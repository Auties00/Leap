package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;

import java.util.Optional;

public sealed interface TlsConfigurableExtension extends TlsExtensionState permits TlsConfigurableClientExtension, TlsConfigurableServerExtension {
    Optional<? extends TlsConfiguredExtension> configure(TlsContext context, int messageLength);
}
