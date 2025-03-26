package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;

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

    public abstract DHPublicKey getOrParsePublicKey();

    private static final class Client extends DHKeyExchange {
        private final byte[] publicKey;
        private final BigInteger p;
        private final BigInteger g;
        private DHPublicKey parsedPublicKey;

        private Client(TlsKeyExchangeType type, byte[] publicKey, BigInteger p, BigInteger g) {
            super(type);
            this.publicKey = publicKey;
            this.p = p;
            this.g = g;
        }

        private Client(TlsKeyExchangeType type, ByteBuffer buffer, BigInteger p, BigInteger g) {
            super(type);
            this.publicKey = readBytesBigEndian16(buffer);
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
        public DHPublicKey getOrParsePublicKey() {
            if(parsedPublicKey != null) {
                return parsedPublicKey;
            }

            try {
                var keyFactory = KeyFactory.getInstance("DH");
                var dhPubKeySpecs = new DHPublicKeySpec(
                        new BigInteger(1, publicKey),
                        p,
                        g
                );
                return parsedPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
            }catch (GeneralSecurityException exception) {
                throw new TlsAlert("Cannot parse DH key", exception);
            }
        }
    }

    private static final class Server extends DHKeyExchange {
        private final byte[] p;
        private final byte[] g;
        private final byte[] publicKey;
        private DHPublicKey parsedPublicKey;

        private Server(TlsKeyExchangeType type, byte[] p, byte[] g, byte[] publicKey) {
            super(type);
            this.p = p;
            this.g = g;
            this.publicKey = publicKey;
        }

        private Server(TlsKeyExchangeType type, ByteBuffer buffer) {
            super(type);
            this.p = readBytesBigEndian16(buffer);
            this.g = readBytesBigEndian16(buffer);
            this.publicKey = readBytesBigEndian16(buffer);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian16(buffer, p);
            writeBytesBigEndian16(buffer, g);
            writeBytesBigEndian16(buffer, publicKey);
        }

        @Override
        public int length() {
            return INT16_LENGTH + p.length
                    + INT16_LENGTH + g.length
                    + INT16_LENGTH + publicKey.length;
        }

        @Override
        public DHPublicKey getOrParsePublicKey() {
            if(parsedPublicKey != null) {
                return parsedPublicKey;
            }

            try {
                var keyFactory = KeyFactory.getInstance("DH");
                var p = new BigInteger(1, this.p);
                var g = new BigInteger(1, this.g);
                var dhPubKeySpecs = new DHPublicKeySpec(
                        new BigInteger(1, publicKey),
                        p,
                        g
                );
                return parsedPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
            }catch (GeneralSecurityException exception) {
                throw new TlsAlert("Cannot parse DH key", exception);
            }
        }
    }

    private record DHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return switch (context.selectedMode().orElseThrow(TlsAlert::noModeSelected)) {
                case CLIENT -> newClientKeyExchange(context);
                case SERVER -> newServerKeyExchange(context);
            };
        }

        private TlsKeyExchange newClientKeyExchange(TlsContext context) {
            var remoteDhKeyExchange = context.remoteKeyExchange()
                    .map(entry -> entry instanceof Server serverKeyExchange ? serverKeyExchange : null)
                    .orElseThrow(() -> new TlsAlert("Missing remote DH key exchange"));
            var keyPair = generateKeyPair(context, remoteDhKeyExchange);
            var publicKey = (DHPublicKey) keyPair.getPublic();
            context.localConnectionState()
                    .setPublicKey(publicKey)
                    .setPrivateKey(keyPair.getPrivate());
            var p = publicKey.getParams()
                    .getP();
            var g = publicKey.getParams()
                    .getG();
            var y = publicKey.getY()
                    .toByteArray();
            return new Client(type, y, p, g);
        }

        private TlsKeyExchange newServerKeyExchange(TlsContext context) {
            var remoteDhKeyExchange = context.remoteKeyExchange()
                    .map(entry -> entry instanceof Client clientKeyExchange ? clientKeyExchange : null)
                    .orElseThrow(() -> new TlsAlert("Missing remote DH key exchange"));
            var keyPair = generateKeyPair(context, remoteDhKeyExchange);
            var publicKey = (DHPublicKey) keyPair.getPublic();
            context.localConnectionState()
                    .setPublicKey(publicKey)
                    .setPrivateKey(keyPair.getPrivate());
            var p = publicKey.getParams()
                    .getP()
                    .toByteArray();
            var g = publicKey.getParams()
                    .getG()
                    .toByteArray();
            var y = publicKey.getY()
                    .toByteArray();
            return new Server(type, p, g, y);
        }

        private KeyPair generateKeyPair(TlsContext context, TlsKeyExchange remoteDhKeyExchange) {
            return context.getNegotiatedValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.supportedGroups()))
                    .stream()
                    .filter(entry -> entry instanceof TlsSupportedFiniteField supportedFiniteField && supportedFiniteField.accepts(remoteDhKeyExchange))
                    .findFirst()
                    .orElseThrow(TlsAlert::noSupportedFiniteField)
                    .generateLocalKeyPair(context);
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            return switch (context.selectedMode().orElseThrow(TlsAlert::noModeSelected)) {
                case SERVER -> {
                    var localPublicKey = context.localConnectionState()
                            .publicKey()
                            .orElseThrow(() -> new TlsAlert("Missing local key pair"));
                    if(!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                        throw new TlsAlert("Unsupported key type");
                    }
                    yield new Client(type, buffer, dhPublicKey.getParams().getP(), dhPublicKey.getParams().getG());
                }
                case CLIENT -> new Server(type, buffer);
            };
        }
    }
}
