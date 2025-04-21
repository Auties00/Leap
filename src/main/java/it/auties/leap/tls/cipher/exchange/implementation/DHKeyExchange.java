package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.preMaster.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;

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
    public TlsPreMasterSecretGenerator preMasterSecretGenerator() {
        return TlsPreMasterSecretGenerator.dh();
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
                    var dhStaticPublicKey = localConnectionState.certificates()
                            .stream()
                            .filter(entry -> entry.value().getPublicKey() instanceof DHPublicKey)
                            .findFirst()
                            .map(entry -> (DHPublicKey) entry.value().getPublicKey())
                            .orElseThrow(() -> new TlsAlert("Expected at least one static DH certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
                    yield switch (localConnectionState.type()) {
                        case CLIENT -> new Client(type, dhStaticPublicKey.getParams().getP(), dhStaticPublicKey.getParams().getG(), dhStaticPublicKey.getY().toByteArray());
                        case SERVER -> new Server(type, dhStaticPublicKey.getParams().getP(), dhStaticPublicKey.getParams().getG(), dhStaticPublicKey.getY().toByteArray());
                    };
                }

                case EPHEMERAL -> switch (localConnectionState.type()) {
                    case CLIENT -> {
                        var remoteKeyExchange = context.remoteConnectionState()
                                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .keyExchange()
                                .orElseThrow(() -> new TlsAlert("No remote key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                        var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                                .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .stream()
                                .filter(entry -> entry instanceof TlsSupportedFiniteField supportedFiniteField
                                        && supportedFiniteField.accepts(remoteKeyExchange))
                                .findFirst()
                                .orElseThrow(() -> new TlsAlert("No supported group is a finite field", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                        var keyPair = group.generateKeyPair(context);
                        var publicKey = (DHPublicKey) keyPair.getPublic();
                        localConnectionState.addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        yield new Client(type, publicKey.getParams().getP(), publicKey.getParams().getG(), publicKey.getY().toByteArray());
                    }
                    case SERVER -> {
                        var group = context.getNegotiatedValue(TlsProperty.supportedGroups())
                                .orElseThrow(() -> new TlsAlert("Missing negotiated property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .stream()
                                .filter(supportedGroup -> supportedGroup instanceof TlsSupportedFiniteField)
                                .map(supportedGroup -> (TlsSupportedFiniteField) supportedGroup)
                                .findFirst()
                                .orElseThrow(() -> new TlsAlert("No supported group is a finite field", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
                        var keyPair = group.generateKeyPair(context);
                        var publicKey = (DHPublicKey) keyPair.getPublic();
                        localConnectionState.addEphemeralKeyPair(TlsKeyPair.of(group, keyPair))
                                .chooseEphemeralKeyPair(group);
                        yield new Server(type, publicKey.getParams().getP(), publicKey.getParams().getG(), publicKey.getY().toByteArray());
                    }
                };
            };
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            var remoteConnectionState = context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            return switch (type) {
                case STATIC -> {
                    if(ephemeralKeyExchangeSource != null) {
                        throw new TlsAlert("Static key exchange should not receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    var dhPublicKey = remoteConnectionState.certificates()
                            .stream()
                            .filter(entry -> entry.value().getPublicKey() instanceof DHPublicKey)
                            .findFirst()
                            .map(entry -> (DHPublicKey) entry.value().getPublicKey())
                            .orElseThrow(() -> new TlsAlert("Missing remote static DH certificate", TlsAlertLevel.FATAL, TlsAlertType.CERTIFICATE_UNOBTAINABLE));
                    yield switch (remoteConnectionState.type()) {
                        case CLIENT -> new Client(type, dhPublicKey.getParams().getP(), dhPublicKey.getParams().getG(), dhPublicKey.getY().toByteArray());
                        case SERVER -> new Server(type, dhPublicKey.getParams().getP(), dhPublicKey.getParams().getG(), dhPublicKey.getY().toByteArray());
                    };
                }

                case EPHEMERAL -> {
                    if(ephemeralKeyExchangeSource == null) {
                        throw new TlsAlert("Ephemeral key exchange should receive an ephemeral key exchange source", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    }

                    yield switch (remoteConnectionState.type()) {
                        case CLIENT -> {
                            var localPublicKey = context.localConnectionState()
                                    .ephemeralKeyPair()
                                    .orElseThrow(() -> new TlsAlert("No ephemeral key pair was generated for local connection", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                    .publicKey();
                            if (!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                                throw new TlsAlert("Remote ephemeral key pair type mismatch: expected DH", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                            }

                            var p = dhPublicKey.getParams().getP();
                            var g = dhPublicKey.getParams().getG();
                            var y = readBytesBigEndian16(ephemeralKeyExchangeSource);
                            yield new Client(type, p, g, y);
                        }

                        case SERVER -> {
                            var p = new BigInteger(1, readBytesBigEndian16(ephemeralKeyExchangeSource));
                            var g = new BigInteger(1, readBytesBigEndian16(ephemeralKeyExchangeSource));
                            var publicKey = readBytesBigEndian16(ephemeralKeyExchangeSource);
                            yield new Server(type, p, g, publicKey);
                        }
                    };
                }
            };
        }
    }
}
