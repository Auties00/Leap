module it.auties.leap {
    // TODO: Drop this dependency
    requires org.bouncycastle.provider;

    exports it.auties.leap.http;

    exports it.auties.leap.socket;
    exports it.auties.leap.socket.async;
    exports it.auties.leap.socket.blocking;

    exports it.auties.leap.tls.certificate;

    exports it.auties.leap.tls.cipher;
    exports it.auties.leap.tls.cipher.exchange;
    exports it.auties.leap.tls.cipher.engine;
    exports it.auties.leap.tls.cipher.mode;
    exports it.auties.leap.tls.version;
    exports it.auties.leap.tls.exception;
    exports it.auties.leap.tls.extension;
    exports it.auties.leap.tls.hash;
    exports it.auties.leap.tls.signature;
    exports it.auties.leap.tls.compression;
    exports it.auties.leap.tls.util;
    exports it.auties.leap.tls.ec;
    exports it.auties.leap.tls.psk;
    exports it.auties.leap.tls.cipher.exchange.client;
    exports it.auties.leap.tls.cipher.exchange.server;
    exports it.auties.leap.tls.mac;
    exports it.auties.leap.tls.group;
    exports it.auties.leap.tls.secret;
    exports it.auties.leap.tls.context;
    exports it.auties.leap.tls.cipher.auth;
    exports it.auties.leap.tls.cipher.engine.implementation;
    exports it.auties.leap.tls.cipher.exchange.client.implementation;
    exports it.auties.leap.tls.cipher.exchange.factory;
    exports it.auties.leap.tls.cipher.exchange.factory.implementation;
    exports it.auties.leap.tls.cipher.exchange.server.implementation;
    exports it.auties.leap.tls.cipher.mode.implementation;
    exports it.auties.leap.socket.blocking.applicationLayer;
    exports it.auties.leap.socket.blocking.transportLayer;
    exports it.auties.leap.socket.blocking.tunnelLayer;
    exports it.auties.leap.socket.async.applicationLayer;
    exports it.auties.leap.socket.async.transportLayer;
    exports it.auties.leap.socket.async.tunnelLayer;
    exports it.auties.leap.http.request;
    exports it.auties.leap.http.response;
    exports it.auties.leap.tls.message;
}