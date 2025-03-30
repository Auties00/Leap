package it.auties.leap.tls.extension;

public sealed interface TlsExtensionOwner {
    sealed interface Client extends TlsExtensionOwner permits TlsExtension.Configured.Client, Agnostic {

    }

    sealed interface Server extends TlsExtensionOwner permits TlsExtension.Configured.Server, Agnostic {

    }

    sealed interface Agnostic extends Client, Server, TlsExtensionOwner permits TlsExtension.Configurable, TlsExtension.Configured.Agnostic {

    }
}
