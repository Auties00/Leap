package it.auties.leap.tls.connection;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public final class TlsConnection {
    public static TlsConnection of(byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        return new TlsConnection(randomData, sessionId, dtlsCookie);
    }

    private final byte[] randomData;
    private final byte[] sessionId;
    private final byte[] dtlsCookie;
    private volatile TlsKeyExchange keyExchange;
    private volatile PublicKey publicKey;
    private volatile PrivateKey privateKey;
    private volatile List<X509Certificate> certificates;
    private volatile TlsCipherMode cipher;
    private TlsConnection(byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.dtlsCookie = dtlsCookie;
    }

    public byte[] randomData() {
        return randomData;
    }

    public byte[] sessionId() {
        return sessionId;
    }

    public Optional<byte[]> dtlsCookie() {
        return Optional.ofNullable(dtlsCookie);
    }

    public Optional<PublicKey> publicKey() {
        return Optional.ofNullable(publicKey);
    }

    public Optional<PrivateKey> privateKey() {
        return Optional.ofNullable(privateKey);
    }

    public List<X509Certificate> certificates() {
        return certificates;
    }

    public Optional<TlsKeyExchange> keyExchange() {
        return Optional.ofNullable(keyExchange);
    }

    public Optional<TlsCipherMode> cipher() {
        return Optional.ofNullable(cipher);
    }

    public TlsConnection setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public TlsConnection setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    public TlsConnection setCertificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public TlsConnection setKeyExchange(TlsKeyExchange keyExchange) {
        this.keyExchange = keyExchange;
        return this;
    }

    public TlsConnection setCipher(TlsCipherMode cipher) {
        this.cipher = cipher;
        return this;
    }
}
