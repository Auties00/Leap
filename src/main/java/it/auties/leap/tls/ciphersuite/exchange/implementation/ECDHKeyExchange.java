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
import it.auties.leap.tls.ec.TlsEcCurveType;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedGroupKeys;
import it.auties.leap.tls.property.TlsProperty;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.interfaces.XECPublicKey;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class ECDHKeyExchange implements TlsKeyExchange {
    private static final TlsKeyExchangeFactory STATIC = new ECDHKeyExchangeFactory(TlsKeyExchangeType.STATIC);
    private static final TlsKeyExchangeFactory EPHEMERAL = new ECDHKeyExchangeFactory(TlsKeyExchangeType.EPHEMERAL);

    public static TlsKeyExchangeFactory staticFactory() {
        return STATIC;
    }

    public static TlsKeyExchangeFactory ephemeralFactory() {
        return EPHEMERAL;
    }

    final TlsKeyExchangeType type;
    private ECDHKeyExchange(TlsKeyExchangeType type) {
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
        if(!(group instanceof TlsSupportedEllipticCurve)) {
            throw new TlsAlert("Unsupported supported group: expected elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        var secret = group.computeSharedSecret(context);
        return Optional.of(secret);
    }

    public abstract Optional<TlsEcCurveType> parameters();

    private static final class Client extends ECDHKeyExchange {
        private final byte[] publicKey;

        private Client(TlsKeyExchangeType type, byte[] publicKey) {
            super(type);
            this.publicKey = publicKey;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT8_LENGTH + publicKey.length;
        }

        @Override
        public Optional<TlsEcCurveType> parameters() {
            return Optional.empty();
        }
    }

    private static final class Server extends ECDHKeyExchange {
        private final TlsEcCurveType parameters;
        private final byte[] publicKey;

        private Server(TlsKeyExchangeType type, TlsEcCurveType parameters, byte[] publicKey) {
            super(type);
            this.parameters = parameters;
            this.publicKey = publicKey;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian8(buffer, publicKey);
        }

        @Override
        public int length() {
            return parameters.length()
                    + INT8_LENGTH + publicKey.length;
        }

        @Override
        public Optional<TlsEcCurveType> parameters() {
            return Optional.ofNullable(parameters);
        }
    }

    private record ECDHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var connectionState = context.localConnectionState();
            return switch (type) {
                case STATIC -> {
                    var publicKey = getStaticPublicKey(connectionState);
                    yield switch (connectionState.type()) {
                        case CLIENT -> {
                            var group = getNegotiatedGroup(context);
                            var y = group.dumpPublicKey(publicKey);
                            yield new Client(type, y);
                        }
                        case SERVER -> {
                            var group = getPreferredGroup(context, null);
                            var y = group.dumpPublicKey(publicKey);
                            yield new Server(type, group.toParameters(), y);
                        }
                    };
                }

                case EPHEMERAL -> switch (context.localConnectionState().type()) {
                    case CLIENT -> {
                        var group = getNegotiatedGroup(context);
                        var keyPair = group.generateKeyPair(context);
                        context.localConnectionState()
                                .addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        var publicKey = group.dumpPublicKey(keyPair.getPublic());
                        yield new Client(type, publicKey);
                    }
                    case SERVER -> {
                        var group = getPreferredGroup(context, null);
                        var keyPair = group.generateKeyPair(context);
                        context.localConnectionState()
                                .addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        var parameters = group.toParameters();
                        var publicKey = group.dumpPublicKey(keyPair.getPublic());
                        yield new Server(type, parameters, publicKey);
                    }
                };
            };
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer source) {
            var connectionState = context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            return switch (type) {
                case STATIC -> {
                    if(source != null) {
                        throw new TlsAlert("Static key exchange should not receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var group = getNegotiatedGroup(context);
                    var publicKey = getStaticPublicKey(connectionState);
                    connectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, publicKey))
                            .chooseEphemeralKeyPair(group);
                    yield null;
                }

                case EPHEMERAL -> {
                    if(source == null) {
                        throw new TlsAlert("Ephemeral key exchange should receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    yield switch (connectionState.type()) {
                        case CLIENT -> {
                            var y = readBytesBigEndian8(source);
                            var group = getPreferredGroup(context, null);
                            var remotePublicKey = group.parsePublicKey(y);
                            connectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, remotePublicKey))
                                    .chooseEphemeralKeyPair(group);
                            yield new Client(type, y);
                        }
                        case SERVER -> {
                            var ecType = readBigEndianInt8(source);
                            var group = getPreferredGroup(context, ecType);
                            var parameters = group.parametersDeserializer()
                                    .deserialize(source);
                            var y = readBytesBigEndian8(source);
                            var publicKey = group.parsePublicKey(y);
                            connectionState.addEphemeralKeyPair(TlsSupportedGroupKeys.of(group, publicKey))
                                    .chooseEphemeralKeyPair(group);
                            yield new Server(type, parameters, y);
                        }
                    };
                }
            };
        }

        private PublicKey getStaticPublicKey(TlsConnection connectionState) {
            return connectionState.certificates()
                    .stream()
                    .filter(entry -> {
                        var publicKey = entry.value().getPublicKey();
                        return publicKey instanceof XDHPublicKey // Curve25519, Curve448, Ed25519, Ed448
                                || publicKey instanceof XECPublicKey // ?
                                || publicKey instanceof ECPublicKey;
                    })
                    .findFirst()
                    .map(entry -> entry.value().getPublicKey())
                    .orElseThrow(() -> new TlsAlert("Expected at least one static ECDH certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
        }

        private TlsSupportedEllipticCurve getNegotiatedGroup(TlsContext context) {
            var remoteKeyExchange = context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .keyExchange()
                    .orElseThrow(() -> new TlsAlert("No remote key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            if(!(remoteKeyExchange instanceof Server remoteEcdhKeyExchange)) {
                throw new TlsAlert("Key exchange mismatch: expected ECDH", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            return remoteEcdhKeyExchange.parameters()
                    .orElseThrow(() -> new TlsAlert("Missing remote ECDH key parameters", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER))
                    .toGroup(context);
        }

        private TlsSupportedEllipticCurve getPreferredGroup(TlsContext context, Byte id) {
            return context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(supportedGroup -> supportedGroup instanceof TlsSupportedEllipticCurve supportedEllipticCurve
                            && (id == null || id.equals(supportedEllipticCurve.parametersDeserializer().id())))
                    .map(supportedGroup -> (TlsSupportedEllipticCurve) supportedGroup)
                    .findFirst()
                    .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        }
    }
}
