package it.auties.leap.tls.extension;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.implementation.StandardExtensionsInitializer;

public interface TlsExtensionsInitializer {
    TlsExtensions process(TlsContext context);

    static TlsExtensionsInitializer standard() {
        return StandardExtensionsInitializer.instance();
    }
}
