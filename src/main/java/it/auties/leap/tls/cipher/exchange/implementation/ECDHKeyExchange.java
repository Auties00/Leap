package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import java.nio.ByteBuffer;
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


    public abstract Optional<TlsECParameters> parameters();

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
        public Optional<TlsECParameters> parameters() {
            return Optional.empty();
        }
    }

    private static final class Server extends ECDHKeyExchange {
        private final TlsECParameters parameters;
        private final byte[] publicKey;

        private Server(TlsKeyExchangeType type, TlsECParameters parameters, byte[] publicKey) {
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
        public Optional<TlsECParameters> parameters() {
            return Optional.ofNullable(parameters);
        }
    }

    private record ECDHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            var localConnectionState = context.localConnectionState();
            return switch (type) {
                case STATIC -> {
                    var certificate = localConnectionState.staticCertificate()
                            .orElseThrow(() -> new TlsAlert("No local static certificate"))
                            .getPublicKey();
                    yield newKeyExchange(localConnectionState, certificate);
                }

                case EPHEMERAL -> {
                    var remoteKeyExchange = context.remoteConnectionState()
                            .orElseThrow(TlsAlert::noRemoteConnectionState)
                            .keyExchange()
                            .orElseThrow(TlsAlert::noRemoteKeyExchange);
                    var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                            .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                            .stream()
                            .filter(entry -> entry instanceof TlsSupportedFiniteField supportedFiniteField
                                    && supportedFiniteField.accepts(remoteKeyExchange))
                            .findFirst()
                            .orElseThrow(TlsAlert::noSupportedFiniteField);
                    var keyPair = group.generateKeyPair(context);
                    var publicKey = (DHPublicKey) keyPair.getPublic();
                    localConnectionState.addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                            .chooseEphemeralKeyPair(group);
                    var p = publicKey.getParams()
                            .getP();
                    var g = publicKey.getParams()
                            .getG();
                    var y = publicKey.getY()
                            .toByteArray();
                    yield switch (localConnectionState.type()) {
                        case CLIENT -> new DHKeyExchange.Client(type, p, g, y);
                        case SERVER -> new DHKeyExchange.Server(type, p, g, y);
                    };
                }
            };

            return switch (context.localConnectionState().type()) {
                case CLIENT -> {
                    var remoteKeyExchange = context.remoteConnectionState()
                            .orElseThrow(TlsAlert::noRemoteConnectionState)
                            .keyExchange()
                            .orElseThrow(TlsAlert::noRemoteKeyExchange);
                    if(!(remoteKeyExchange instanceof Server remoteEcdhKeyExchange)) {
                        throw TlsAlert.keyExchangeTypeMismatch("ECDH");
                    }

                    var group = remoteEcdhKeyExchange.parameters()
                            .orElseThrow(() -> new TlsAlert("Missing remote ECDH key parameters"))
                            .toGroup(context);
                    var keyPair = group.generateKeyPair(context);
                    context.localConnectionState()
                            .addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                            .chooseEphemeralKeyPair(group);
                    var publicKey = group.dumpPublicKey(keyPair.getPublic());
                    yield  new Client(type, publicKey);
                }
                case SERVER -> newServerKeyExchange(context);
            };
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
                            .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()));
                    var ecType = readBigEndianInt8(ephemeralKeyExchangeSource);
                    var parameters = supportedGroups.stream()
                            .filter(group -> group instanceof TlsSupportedEllipticCurve supportedEllipticCurve
                                    && supportedEllipticCurve.parametersDeserializer().accepts(ecType))
                            .findFirst()
                            .map(group -> (TlsSupportedEllipticCurve) group)
                            .orElseThrow(TlsAlert::noSupportedEllipticCurve)
                            .parametersDeserializer()
                            .deserialize(ephemeralKeyExchangeSource);
                    var publicKey = readBytesBigEndian8(ephemeralKeyExchangeSource);
                    yield new Server(type, parameters, publicKey);
                }
            };
        }

        private Server newServerKeyExchange(TlsContext context) {
            var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                    .stream()
                    .filter(supportedGroup -> supportedGroup instanceof TlsSupportedEllipticCurve)
                    .map(supportedGroup -> (TlsSupportedEllipticCurve) supportedGroup)
                    .findFirst()
                    .orElseThrow(TlsAlert::noSupportedEllipticCurve);
            var keyPair = group.generateKeyPair(context);
            context.localConnectionState()
                    .addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                    .chooseEphemeralKeyPair(group);
            var parameters = group.toParameters();
            var publicKey = group.dumpPublicKey(keyPair.getPublic());
            return new Server(type, parameters, publicKey);
        }
    }
}
