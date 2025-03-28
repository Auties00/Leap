package it.auties.leap.tls.extension;

public sealed interface TlsExtensionState permits TlsConfigurableExtension, TlsConfiguredExtension {
    int extensionType();
    TlsExtensionDependencies dependencies();
}
