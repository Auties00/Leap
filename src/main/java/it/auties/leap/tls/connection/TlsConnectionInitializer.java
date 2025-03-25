package it.auties.leap.tls.connection;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.connection.implementation.StandardConnectionInitializer;

public interface TlsConnectionInitializer {
    static TlsConnectionInitializer standard() {
        return StandardConnectionInitializer.instance();
    }

    void initialize(TlsContext context, TlsConnection state);
}
