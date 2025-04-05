package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;

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
                        case CLIENT -> new Client(type, p, g, y);
                        case SERVER -> new Server(type, p, g, y);
                    };
                }
            };
        }

        @Override
        public TlsKeyExchange newRemoteKeyExchange(TlsContext context, ByteBuffer ephemeralKeyExchangeSource) {
            var remoteConnectionState = context.remoteConnectionState()
                    .orElseThrow(TlsAlert::noRemoteConnectionState);
            return switch (type) {
                case STATIC -> {
                    if(ephemeralKeyExchangeSource != null) {
                        throw new TlsAlert("Static key exchange should not receive an ephemeral key exchange source");
                    }

                    var certificate = remoteConnectionState.staticCertificate()
                            .orElseThrow(() -> new TlsAlert("No remote static certificate"))
                            .getPublicKey();
                    yield newKeyExchange(remoteConnectionState, certificate);
                }

                case EPHEMERAL -> {
                    if(ephemeralKeyExchangeSource == null) {
                        throw new TlsAlert("Ephemeral key exchange should receive an ephemeral key exchange source");
                    }

                    yield switch (remoteConnectionState.type()) {
                        case CLIENT -> {
                            var localPublicKey = context.localConnectionState()
                                    .ephemeralKeyPair()
                                    .orElseThrow(TlsAlert::noKeyPairSelected)
                                    .publicKey();
                            if (!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                                throw TlsAlert.keyExchangeTypeMismatch("DH");
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

        private TlsKeyExchange newKeyExchange(TlsConnection connection, PublicKey certificate) {
            if(!(certificate instanceof DHPublicKey dhPublicKey)) {
                throw TlsAlert.keyExchangeTypeMismatch("DH");
            }

            var p = dhPublicKey.getParams().getP();
            var g = dhPublicKey.getParams().getG();
            var y = dhPublicKey.getY().toByteArray();
            return switch (connection.type()) {
                case CLIENT -> new Client(type, p, g, y);
                case SERVER -> new Server(type, p, g, y);
            };
        }
    }
}
