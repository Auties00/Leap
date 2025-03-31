package it.auties.leap.tls.extension;

import it.auties.leap.tls.version.TlsVersion;

import java.util.List;

public sealed interface TlsExtensionMetadataProvider permits TlsExtension, TlsExtensionOwner, TlsExtensionState {
    int extensionType();
    List<TlsVersion> versions();
    TlsExtensionDependencies dependencies();
}
