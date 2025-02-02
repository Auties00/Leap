module it.auties.leap {
    // TODO: Drop this dependency
    requires org.bouncycastle.provider;

    exports it.auties.leap.http;

    exports it.auties.leap.socket;
    exports it.auties.leap.socket.implementation;
    exports it.auties.leap.socket.transport;
    exports it.auties.leap.socket.tunnel;

    exports it.auties.leap.tls.certificate;

    exports it.auties.leap.tls.cipher;
    exports it.auties.leap.tls.cipher.auth;
    exports it.auties.leap.tls.cipher.exchange;
    exports it.auties.leap.tls.cipher.engine;
    exports it.auties.leap.tls.cipher.mode;
    exports it.auties.leap.tls.version;
    exports it.auties.leap.tls.exception;
    exports it.auties.leap.tls.extension;
    exports it.auties.leap.tls.hash;
    exports it.auties.leap.tls.key;
    exports it.auties.leap.tls.signature;
    exports it.auties.leap.tls.compression;
    exports it.auties.leap.tls.util;
    exports it.auties.leap.tls;
    exports it.auties.leap.tls.ec;
    exports it.auties.leap.tls.psk;
    exports it.auties.leap.tls.cipher.exchange.client;
    exports it.auties.leap.tls.cipher.exchange.server;
    exports it.auties.leap.socket.implementation.bridge;
}