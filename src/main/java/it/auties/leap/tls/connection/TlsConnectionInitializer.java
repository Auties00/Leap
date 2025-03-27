package it.auties.leap.tls.connection;

import it.auties.leap.tls.connection.implementation.StandardConnectionInitializer;
import it.auties.leap.tls.context.TlsContext;

public interface TlsConnectionInitializer {
    void initialize(TlsContext context);

    static TlsConnectionInitializer standard() {
        return StandardConnectionInitializer.instance();
    }
}
