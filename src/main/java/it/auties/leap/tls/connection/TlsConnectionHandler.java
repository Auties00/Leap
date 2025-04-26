package it.auties.leap.tls.connection;

import it.auties.leap.tls.connection.implementation.ConnectionHandler;
import it.auties.leap.tls.context.TlsContext;

public interface TlsConnectionHandler {
    void initialize(TlsContext context);
    void finalize(TlsContext context);

    static TlsConnectionHandler builtin() {
        return ConnectionHandler.instance();
    }
}
