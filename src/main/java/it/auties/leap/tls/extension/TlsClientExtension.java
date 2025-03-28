package it.auties.leap.tls.extension;

public sealed interface TlsClientExtension extends TlsExtension permits TlsConfigurableClientExtension, TlsConfiguredClientExtension {

}
