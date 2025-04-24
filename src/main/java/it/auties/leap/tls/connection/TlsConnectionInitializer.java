package it.auties.leap.tls.connection;

import it.auties.leap.tls.connection.implementation.ConnectionInitializer;
import it.auties.leap.tls.context.TlsContext;

public interface TlsConnectionInitializer {
    void initialize(TlsContext context);

    static TlsConnectionInitializer builtin() {
        return ConnectionInitializer.instance();
    }
}
