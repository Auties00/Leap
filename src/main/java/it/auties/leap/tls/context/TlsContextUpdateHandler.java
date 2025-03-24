package it.auties.leap.tls.context;

public interface TlsContextUpdateHandler {
    static TlsContextUpdateHandler standard() {
        return new TlsContextUpdateHandler() {
            @Override
            public void assertValid(TlsContext context, TlsContextUpdate update) {

            }
        };
    }

    void assertValid(TlsContext context, TlsContextUpdate update);
}
