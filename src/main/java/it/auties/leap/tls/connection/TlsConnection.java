package it.auties.leap.tls.connection;

import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipher;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.group.TlsSupportedGroupKeys;
import it.auties.leap.tls.message.TlsHandshakeMessageFlow;

import java.util.*;

public final class TlsConnection {
    private final TlsConnectionType type;

    private final byte[] randomData;
    private final byte[] sessionId;
    private final byte[] dtlsCookie;
    private final List<TlsCertificate> certificates;

    private final Map<Integer, TlsSupportedGroupKeys> ephemeralKeyPairs;
    private volatile Integer selectedEphemeralKeyPair;
    private volatile TlsCertificate selectedStaticCertificate;

    private volatile TlsKeyExchange keyExchange;

    private volatile TlsCipher cipher;

    private final TlsHandshakeMessageFlow handshakeFlow;
    private volatile TlsConnectionHandshakeStatus handshakeStatus;
    private volatile TlsConnectionSecret handshakeSecret;

    private TlsConnection(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie, List<TlsCertificate> certificates) {
        this.type = type;
        this.randomData = randomData;
        this.sessionId = sessionId;
        this.dtlsCookie = dtlsCookie;
        this.ephemeralKeyPairs = new HashMap<>();
        this.handshakeStatus = TlsConnectionHandshakeStatus.HANDSHAKE_WAIT;
        this.certificates = certificates;
        this.handshakeFlow = TlsHandshakeMessageFlow.of(type);
    }

    public static TlsConnection of(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie) {
        return of(type, randomData, sessionId, dtlsCookie, new ArrayList<>());
    }

    public static TlsConnection of(TlsConnectionType type, byte[] randomData, byte[] sessionId, byte[] dtlsCookie, List<TlsCertificate> certificates) {
        Objects.requireNonNull(type, "Type cannot be null");
        Objects.requireNonNull(randomData, "Random data cannot be null");
        Objects.requireNonNull(sessionId, "Session ID cannot be null");
        Objects.requireNonNull(certificates, "Certificates cannot be null");
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

    public Optional<TlsSupportedGroupKeys> ephemeralKeyPair() {
        if(selectedEphemeralKeyPair == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(ephemeralKeyPairs.get(selectedEphemeralKeyPair));
    }

    public TlsConnectionHandshakeStatus handshakeStatus() {
        return handshakeStatus;
    }

    public TlsConnection addEphemeralKeyPair(TlsSupportedGroupKeys keyPair) {
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

    public TlsConnection setHandshakeStatus(TlsConnectionHandshakeStatus handshakeStatus) {
        this.handshakeStatus = handshakeStatus;
        return this;
    }

    public boolean chooseEphemeralKeyPair(TlsSupportedGroup group) {
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
        if(!certificates.contains(certificate)) {
            return false;
        }

        this.selectedStaticCertificate = certificate;
        return true;
    }

    public TlsConnection setHandshakeSecret(TlsConnectionSecret handshakeSecret) {
        this.handshakeSecret = handshakeSecret;
        return this;
    }

    public Optional<TlsConnectionSecret> handshakeSecret() {
        return Optional.ofNullable(handshakeSecret);
    }

    public TlsHandshakeMessageFlow handshakeFlow() {
        return handshakeFlow;
    }
}
