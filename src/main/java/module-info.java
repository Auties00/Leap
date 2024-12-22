module it.auties.leap {
    // TODO: Drop this dependency
    requires org.bouncycastle.provider;

    exports it.auties.leap.http;

    exports it.auties.leap.socket;

    exports it.auties.leap.tls.certificate;

    exports it.auties.leap.tls.cipher;
    exports it.auties.leap.tls.cipher.auth;
    exports it.auties.leap.tls.cipher.exchange;
    exports it.auties.leap.tls.cipher.engine;
    exports it.auties.leap.tls.cipher.mode;

    exports it.auties.leap.tls.config;

    exports it.auties.leap.tls.exception;

    exports it.auties.leap.tls.extension;

    exports it.auties.leap.tls.hash;

    exports it.auties.leap.tls.key;

    exports it.auties.leap.tls.signature;
}