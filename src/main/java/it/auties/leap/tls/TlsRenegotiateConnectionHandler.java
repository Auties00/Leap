package it.auties.leap.tls;

import it.auties.leap.tls.engine.TlsEngine;

@FunctionalInterface
public interface TlsRenegotiateConnectionHandler {
    void renegotiate(TlsEngine engine);
}
