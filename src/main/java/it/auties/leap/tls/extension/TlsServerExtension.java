package it.auties.leap.tls.extension;

public sealed interface TlsServerExtension extends TlsExtension permits TlsConfigurableServerExtension, TlsConfiguredServerExtension {
}
