package it.auties.leap.tls.ciphersuite.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchange;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.group.TlsSupportedGroupKeys;
import it.auties.leap.tls.property.TlsProperty;

import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public abstract sealed class DHKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory STATIC = new DHKeyExchangeFactory(TlsKeyExchangeType.STATIC);
    private static final TlsKeyExchangeFactory EPHEMERAL = new DHKeyExchangeFactory(TlsKeyExchangeType.EPHEMERAL);

    public static TlsKeyExchangeFactory staticFactory() {
        return STATIC;
    }

    public static TlsKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL;
    }

    final TlsKeyExchangeType type;
    private DHKeyExchange(TlsKeyExchangeType type) {
        this.type = type;
    }

    @Override
    public TlsKeyExchangeType type() {
        return type;
    }

    @Override
    public Optional<TlsConnectionSecret> generatePreSharedSecret(TlsContext context) {
        var group = context.localConnectionState()
                .ephemeralKeyPair()
                .orElseThrow(() -> new TlsAlert("No ephemeral key pair was generated for local connection", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .group();
        if(!(group instanceof TlsSupportedFiniteField)) {
            throw new TlsAlert("Unsupported supported group: expected finite field", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        var secret = group.computeSharedSecret(context);
        return Optional.of(secret);
    }

    public abstract BigInteger p();

    public abstract BigInteger g();

    private static final class Client extends DHKeyExchange {
        private final byte[] publicKey;
        private final BigInteger p;
        private final BigInteger g;

        private Client(TlsKeyExchangeType type, BigInteger p, BigInteger g, byte[] publicKey) {
            super(type);
            this.publicKey = publicKey;
            this.p = p;
            this.g = g;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + publicKey.length;
        }

        @Override
        public BigInteger p() {
            return p;
        }

        @Override
        public BigInteger g() {
            return g;
        }
    }

    private static final class Server extends DHKeyExchange {
        private final BigInteger p;
        private final BigInteger g;
        private final byte[] publicKey;

        private Server(TlsKeyExchangeType type, BigInteger p, BigInteger g, byte[] publicKey) {
            super(type);
            this.p = p;
            this.g = g;
            this.publicKey = publicKey;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, p.toByteArray());
            writeBytesBigEndian16(buffer, g.toByteArray());
            writeBytesBigEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + (p.bitLength() + 8) / 8
                    + INT16_LENGTH + (g.bitLength() + 8) / 8
                    + INT16_LENGTH + publicKey.length;
        }

        @Override
        public BigInteger p() {
            return p;
        }

        @Override
        public BigInteger g() {
            return g;
        }
    }

    private record DHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var localConnectionState = context.localConnectionState();
            return switch (type) {
                case STATIC -> {
                    var publicKey = getStaticPublicKey(localConnectionState);
                    var group = getPreferredGroup(context);
                    localConnectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, publicKey))
                            .chooseEphemeralKeyPair(group);
                    yield null;
                }

                case EPHEMERAL -> switch (localConnectionState.type()) {
                    case CLIENT -> {
                        var remoteKeyExchange = context.remoteConnectionState()
                                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .keyExchange()
                                .orElseThrow(() -> new TlsAlert("No remote key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                        var group = getNegotiatedGroup(context, remoteKeyExchange);
                        var keyPair = group.generateKeyPair(context);
                        var publicKey = (DHPublicKey) keyPair.getPublic();
                        localConnectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        yield new Client(type, publicKey.getParams().getP(), publicKey.getParams().getG(), publicKey.getY().toByteArray());
                    }
                    case SERVER -> {
                        var group = getPreferredGroup(context);
                        var keyPair = group.generateKeyPair(context);
                        var publicKey = (DHPublicKey) keyPair.getPublic();
                        localConnectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        yield new Server(type, publicKey.getParams().getP(), publicKey.getParams().getG(), publicKey.getY().toByteArray());
                    }
                };
            };
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
            var remoteConnectionState = context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            return switch (type) {
                case STATIC -> {
                    if(source != null) {
                        throw new TlsAlert("Static key exchange should not receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var group = getPreferredGroup(context);
                    var remotePublicKey = getStaticPublicKey(remoteConnectionState);
                    remoteConnectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, remotePublicKey))
                            .chooseEphemeralKeyPair(group);
                    yield null;
                }

                case EPHEMERAL -> {
                    if(source == null) {
                        throw new TlsAlert("Ephemeral key exchange should receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    yield switch (remoteConnectionState.type()) {
                        case CLIENT -> {
                            var localPublicKey = getEphemeralPublicKey(context);
                            var p = localPublicKey.getParams().getP();
                            var g = localPublicKey.getParams().getG();
                            var y = readBytesBigEndian16(source);
                            var group = getPreferredGroup(context);
                            var publicKey = group.parsePublicKey(y);
                            var keys = TlsSupportedGroupKeys.of(group, publicKey);
                            remoteConnectionState.addEphemeralKeyPair(keys)
                                    .chooseEphemeralKeyPair(group);
                            yield new Client(type, p, g, y);
                        }

                        case SERVER -> {
                            var p = new BigInteger(1, readBytesBigEndian16(source));
                            var g = new BigInteger(1, readBytesBigEndian16(source));
                            var y = readBytesBigEndian16(source);
                            var remoteKeyExchange = new Server(type, p, g, y);
                            var group = getNegotiatedGroup(context, remoteKeyExchange);
                            var publicKey = group.parsePublicKey(y);
                            var keys = TlsSupportedGroupKeys.of(group, publicKey);
                            remoteConnectionState.addEphemeralKeyPair(keys)
                                    .chooseEphemeralKeyPair(group);
                            yield remoteKeyExchange;
                        }
                    };
                }
            };
        }

        private DHPublicKey getStaticPublicKey(TlsConnection connectionState) {
            return connectionState.certificates()
                    .stream()
                    .filter(entry -> entry.value().getPublicKey() instanceof DHPublicKey)
                    .findFirst()
                    .map(entry -> (DHPublicKey) entry.value().getPublicKey())
                    .orElseThrow(() -> new TlsAlert("Expected at least one static DH certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
        }

        private DHPublicKey getEphemeralPublicKey(TlsContext context) {
            var localPublicKey = context.localConnectionState()
                    .ephemeralKeyPair()
                    .orElseThrow(() -> new TlsAlert("No ephemeral key pair was generated for local connection", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .publicKey();
            if (!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                throw new TlsAlert("Remote ephemeral key pair type mismatch: expected DH", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
            return dhPublicKey;
        }


        private TlsSupportedGroup getNegotiatedGroup(TlsContext context, TlsKeyExchange remoteKeyExchange) {
            return context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(entry -> entry instanceof TlsSupportedFiniteField supportedFiniteField
                            && supportedFiniteField.accepts(remoteKeyExchange))
                    .findFirst()
                    .orElseThrow(() -> new TlsAlert("No supported group is a finite field", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        }

        private TlsSupportedFiniteField getPreferredGroup(TlsContext context) {
            return context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(supportedGroup -> supportedGroup instanceof TlsSupportedFiniteField)
                    .map(supportedGroup -> (TlsSupportedFiniteField) supportedGroup)
                    .findFirst()
                    .orElseThrow(() -> new TlsAlert("No supported group is a finite field", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        }
    }
}
