package it.auties.leap.tls.connection.initializer;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.connection.initializer.implementation.StandardConnectionInitializer;

public interface TlsConnectionInitializer {
    static TlsConnectionInitializer standard() {
        return StandardConnectionInitializer.instance();
    }

    void initialize(TlsContext context);
}
