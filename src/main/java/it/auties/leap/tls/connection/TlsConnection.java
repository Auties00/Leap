package it.auties.leap.tls.connection;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedGroup;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class TlsConnection {
    public static TlsConnection of(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        return new TlsConnection(type, randomData, sessionId, dtlsCookie);
    }

    private final TlsConnectionType type;
    private final byte[] randomData;
    private final byte[] sessionId;
    private final byte[] dtlsCookie;
    private final Map<Integer, TlsKeyPair> keys;
    private volatile TlsKeyExchange keyExchange;
    private volatile X509Certificate staticCertificate;
    private volatile TlsCipher cipher;
    private volatile TlsHandshakeStatus handshakeStatus;
    private volatile Integer selectedKeyPair;
    private TlsConnection(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        this.type = type;
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.dtlsCookie = dtlsCookie;
        this.keys = new HashMap<>();
        this.handshakeStatus = TlsHandshakeStatus.HANDSHAKE_WAIT;
    }

    public TlsConnectionType type() {
        return type;
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

    public Optional<X509Certificate> staticCertificate() {
        return Optional.ofNullable(staticCertificate);
    }

    public Optional<TlsKeyExchange> keyExchange() {
        return Optional.ofNullable(keyExchange);
    }

    public Optional<TlsCipher> cipher() {
        return Optional.ofNullable(cipher);
    }

    public TlsConnection addEphemeralKeyPair(TlsKeyPair keyPair) {
        keys.put(keyPair.group().id(), keyPair);
        return this;
    }

    public boolean chooseEphemeralKeyPair(TlsSupportedGroup group) {
        if(!keys.containsKey(group.id())) {
            return false;
        }

        this.selectedKeyPair = group.id();
        return true;
    }

    public Optional<TlsKeyPair> ephemeralKeyPair() {
        if(selectedKeyPair == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(keys.get(selectedKeyPair));
    }

    public TlsConnection setStaticCertificate(X509Certificate staticCertificate) {
        this.staticCertificate = staticCertificate;
        return this;
    }

    public TlsConnection setKeyExchange(TlsKeyExchange keyExchange) {
        this.keyExchange = keyExchange;
        return this;
    }

    public TlsConnection setCipher(TlsCipher cipher) {
        this.cipher = cipher;
        return this;
    }

    public TlsHandshakeStatus handshakeStatus() {
        return handshakeStatus;
    }

    public TlsConnection setHandshakeStatus(TlsHandshakeStatus handshakeStatus) {
        this.handshakeStatus = handshakeStatus;
        return this;
    }
}
