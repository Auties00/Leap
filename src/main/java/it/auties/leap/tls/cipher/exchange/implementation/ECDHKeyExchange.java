package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsEcParameters;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.nio.ByteBuffer;
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
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.ecdh();
    }


    public abstract Optional<TlsEcParameters> parameters();

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
        public Optional<TlsEcParameters> parameters() {
            return Optional.empty();
        }
    }

    private static final class Server extends ECDHKeyExchange {
        private final TlsEcParameters parameters;
        private final byte[] publicKey;

        private Server(TlsKeyExchangeType type, TlsEcParameters parameters, byte[] publicKey) {
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
        public Optional<TlsEcParameters> parameters() {
            return Optional.ofNullable(parameters);
        }
    }

    private record ECDHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var localConnectionState = context.localConnectionState();
            return switch (type) {
                case STATIC -> {
                    var ecdhStaticPublicKey = localConnectionState.certificates()
                            .stream()
                            .filter(entry -> {
                                var publicKey = entry.value().getPublicKey();
                                return publicKey instanceof XDHPublicKey // Curve25519, Curve448, Ed25519, Ed448
                                        || publicKey instanceof XECPublicKey // ?
                                        || publicKey instanceof ECPublicKey; // Other
                            })
                            .findFirst()
                            .map(entry -> entry.value().getPublicKey())
                            .orElseThrow(() -> new TlsAlert("Expected at least one static ECDH certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
                    yield switch (context.localConnectionState().type()) {
                        case CLIENT -> {
                            var group = getRemoteECGroup(context);
                            yield new Client(type, group.dumpPublicKey(ecdhStaticPublicKey));
                        }
                        case SERVER -> {
                            var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                    .stream()
                                    .filter(supportedGroup -> supportedGroup instanceof TlsSupportedEllipticCurve)
                                    .map(supportedGroup -> (TlsSupportedEllipticCurve) supportedGroup)
                                    .findFirst()
                                    .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                            yield new Server(type, group.toParameters(), group.dumpPublicKey(ecdhStaticPublicKey));
                        }
                    };
                }

                case EPHEMERAL -> switch (context.localConnectionState().type()) {
                    case CLIENT -> {
                        var group = getRemoteECGroup(context);
                        var keyPair = group.generateKeyPair(context);
                        context.localConnectionState()
                                .addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        var publicKey = group.dumpPublicKey(keyPair.getPublic());
                        yield new Client(type, publicKey);
                    }
                    case SERVER -> {
                        var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                                .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .stream()
                                .filter(supportedGroup -> supportedGroup instanceof TlsSupportedEllipticCurve)
                                .map(supportedGroup -> (TlsSupportedEllipticCurve) supportedGroup)
                                .findFirst()
                                .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                        var keyPair = group.generateKeyPair(context);
                        context.localConnectionState()
                                .addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        var parameters = group.toParameters();
                        var publicKey = group.dumpPublicKey(keyPair.getPublic());
                        yield new Server(type, parameters, publicKey);
                    }
                };
            };
        }

        private TlsSupportedEllipticCurve getRemoteECGroup(TlsContext context) {
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

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            return switch (context.localConnectionState().type()) {
                case SERVER -> {
                    var publicKey = readBytesBigEndian8(ephemeralKeyExchangeSource);
                    yield new Client(type, publicKey);
                }
                case CLIENT -> {
                    var supportedGroups = context.getNegotiatedValue(TlsProperty.supportedGroups())
                            .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                    var ecType = readBigEndianInt8(ephemeralKeyExchangeSource);
                    var parameters = supportedGroups.stream()
                            .filter(group -> group instanceof TlsSupportedEllipticCurve supportedEllipticCurve
                                    && supportedEllipticCurve.parametersDeserializer().accepts(ecType))
                            .findFirst()
                            .map(group -> (TlsSupportedEllipticCurve) group)
                            .orElseThrow(() -> new TlsAlert("No supported group is an elliptic curve", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER))
                            .parametersDeserializer()
                            .deserialize(ephemeralKeyExchangeSource);
                    var publicKey = readBytesBigEndian8(ephemeralKeyExchangeSource);
                    yield new Server(type, parameters, publicKey);
                }
            };
        }
    }
}
