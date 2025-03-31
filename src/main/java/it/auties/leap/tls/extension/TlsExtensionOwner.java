package it.auties.leap.tls.extension;

public sealed interface TlsExtensionOwner extends TlsExtensionMetadataProvider {
    sealed interface Client extends TlsExtensionOwner permits TlsExtension.Configurable, TlsExtension.Configured.Client {

    }

    sealed interface Server extends TlsExtensionOwner permits TlsExtension.Configurable, TlsExtension.Configured.Server {

    }
}
