module it.auties.leap {
    // TODO: Drop this dependency
    requires org.bouncycastle.provider;

    // Exports HTTP module
    exports it.auties.leap.http;

    // Exports SOCKET module
    exports it.auties.leap.socket;

    // Exports TLS module
    exports it.auties.leap.tls;

    exports it.auties.leap.tls.cipher;
    exports it.auties.leap.tls.cipher.engine;
    exports it.auties.leap.tls.cipher.mode;

    exports it.auties.leap.tls.extension;
    exports it.auties.leap.tls.exception;
    exports it.auties.leap.tls.config;
    exports it.auties.leap.tls.certificate;
    exports it.auties.leap.tls.key;
    exports it.auties.leap.tls.hash;
    exports it.auties.leap.tls.message;
    exports it.auties.leap.tls.cipher.exchange;
    exports it.auties.leap.tls.cipher.auth;
    exports it.auties.leap.tls.cipher.exchange.client;
    exports it.auties.leap.tls.cipher.exchange.server;
}