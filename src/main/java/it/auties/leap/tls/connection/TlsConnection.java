package it.auties.leap.tls.connection;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedGroup;

import java.util.*;

public final class TlsConnection {
    private final TlsConnectionType type;

    private final byte[] randomData;
    private final byte[] sessionId;
    private final byte[] dtlsCookie;
    private final List<TlsCertificate> certificates;

    private final Map<Integer, TlsKeyPair> ephemeralKeyPairs;
    private volatile Integer selectedEphemeralKeyPair;
    private volatile TlsCertificate selectedStaticCertificate;

    private volatile TlsKeyExchange keyExchange;

    private volatile TlsCipher cipher;
    private volatile TlsHandshakeStatus handshakeStatus;

    private TlsConnection(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie, List<TlsCertificate> certificates) {
        this.type = type;
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.dtlsCookie = dtlsCookie;
        this.ephemeralKeyPairs = new HashMap<>();
        this.handshakeStatus = TlsHandshakeStatus.HANDSHAKE_WAIT;
        this.certificates = certificates;
    }

    public static TlsConnection newConnection(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        return new TlsConnection(type, randomData, sessionId, dtlsCookie, new ArrayList<>());
    }

    public static TlsConnection newConnection(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie, List<TlsCertificate> certificates) {
        if(type == null) {
            throw new NullPointerException("type");
        }

        if(randomData == null) {
            throw new NullPointerException("randomData");
        }

        if(certificates == null) {
            throw new NullPointerException("certificates");
        }

        return new TlsConnection(type, randomData, sessionId, dtlsCookie, certificates);
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

    public Optional<TlsKeyExchange> keyExchange() {
        return Optional.ofNullable(keyExchange);
    }

    public Optional<TlsCipher> cipher() {
        return Optional.ofNullable(cipher);
    }

    public Optional<TlsKeyPair> ephemeralKeyPair() {
        if(selectedEphemeralKeyPair == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(ephemeralKeyPairs.get(selectedEphemeralKeyPair));
    }

    public TlsHandshakeStatus handshakeStatus() {
        return handshakeStatus;
    }

    public TlsConnection addEphemeralKeyPair(TlsKeyPair keyPair) {
        ephemeralKeyPairs.put(keyPair.group().id(), keyPair);
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

    public TlsConnection setHandshakeStatus(TlsHandshakeStatus handshakeStatus) {
        this.handshakeStatus = handshakeStatus;
        return this;
    }

    public boolean chooseEphemeralKeyPair(TlsSupportedGroup group) {
        if(keyExchange == null || keyExchange.type() != TlsKeyExchangeType.EPHEMERAL || selectedEphemeralKeyPair != null) {
            return false;
        }

        if(!ephemeralKeyPairs.containsKey(group.id())) {
            return false;
        }

        this.selectedEphemeralKeyPair = group.id();
        return true;
    }

    public TlsConnection addCertificate(TlsCertificate certificate) {
        certificates.add(certificate);
        return this;
    }

    public boolean removeCertificate(TlsCertificate certificate) {
        return certificates.remove(certificate);
    }

    public Collection<TlsCertificate> certificates() {
        return Collections.unmodifiableCollection(certificates);
    }

    public Optional<TlsCertificate> staticCertificate() {
        return Optional.ofNullable(selectedStaticCertificate);
    }

    public boolean chooseStaticCertificate(TlsCertificate certificate) {
        if(keyExchange == null || keyExchange.type() != TlsKeyExchangeType.STATIC || selectedStaticCertificate != null) {
            return false;
        }

        if(!certificates.contains(certificate)) {
            return false;
        }

        this.selectedStaticCertificate = certificate;
        return true;
    }
}
