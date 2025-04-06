module it.auties.leap {
    requires org.bouncycastle.provider; // TODO: Drop this dependency

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
    exports it.auties.leap.tls.extension;
    exports it.auties.leap.tls.hash;
    exports it.auties.leap.tls.signature;
    exports it.auties.leap.tls.compression;
    exports it.auties.leap.tls.ec;
    exports it.auties.leap.tls.psk;
    exports it.auties.leap.tls.group;
    exports it.auties.leap.tls.connection;
    exports it.auties.leap.tls.cipher.auth;
    exports it.auties.leap.socket.blocking.applicationLayer;
    exports it.auties.leap.socket.blocking.transportLayer;
    exports it.auties.leap.socket.blocking.tunnelLayer;
    exports it.auties.leap.socket.async.applicationLayer;
    exports it.auties.leap.socket.async.transportLayer;
    exports it.auties.leap.socket.async.tunnelLayer;
    exports it.auties.leap.http.exchange.request;
    exports it.auties.leap.http.exchange.response;
    exports it.auties.leap.tls.message;
    exports it.auties.leap.http.config;
    exports it.auties.leap.http.exchange.body;
    exports it.auties.leap.http.exchange;
    exports it.auties.leap.http.exchange.headers;
    exports it.auties.leap.tls.message.implementation;
    exports it.auties.leap.tls.property;
    exports it.auties.leap.tls.alert;
    exports it.auties.leap.tls.context;
    exports it.auties.leap.tls.secret;
    exports it.auties.leap.tls.name;
    exports it.auties.leap.tls.compressor;
    exports it.auties.leap.tls.srtp;
}