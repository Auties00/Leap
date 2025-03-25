package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.ec.TlsECParameters;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.group.TlsSupportedEllipticCurve;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.connection.preMasterSecret.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;
import java.util.List;
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

    public abstract byte[] publicKey();

    public abstract Optional<TlsECParameters> parameters();

    private static final class Client extends ECDHKeyExchange {
        private final byte[] publicKey;

        private Client(TlsKeyExchangeType type, byte[] publicKey) {
            super(type);
            this.publicKey = publicKey;
        }

        private Client(TlsKeyExchangeType type, ByteBuffer buffer) {
            super(type);
            this.publicKey = readBytesBigEndian8(buffer);
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
        public byte[] publicKey() {
            return publicKey;
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

        private Server(TlsKeyExchangeType type, ByteBuffer buffer, List<TlsSupportedGroup> supportedGroups) {
            super(type);
            var ecType = readBigEndianInt8(buffer);
            this.parameters = supportedGroups.stream()
                    .filter(group -> group instanceof TlsSupportedEllipticCurve supportedEllipticCurve && supportedEllipticCurve.accepts(ecType))
                    .findFirst()
                    .map(group -> (TlsSupportedEllipticCurve) group)
                    .orElseThrow(TlsException::noSupportedEllipticCurve)
                    .parametersDeserializer()
                    .deserialize(buffer);
            this.publicKey = readBytesBigEndian8(buffer);
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
        public byte[] publicKey() {
            return publicKey;
        }

        @Override
        public Optional<TlsECParameters> parameters() {
            return Optional.ofNullable(parameters);
        }
    }

    private record ECDHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return switch (context.selectedMode().orElseThrow(TlsException::noModeSelected)) {
                case CLIENT -> newClientKeyExchange(context);
                case SERVER -> newServerKeyExchange(context);
            };
        }

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            return switch (context.selectedMode().orElseThrow(TlsException::noModeSelected)) {
                case SERVER -> new Client(type, buffer);
                case CLIENT -> {
                    var supportedGroups = context.getNegotiatedValue(TlsProperty.supportedGroups())
                            .orElseThrow(() -> TlsException.noNegotiatedProperty(TlsProperty.supportedGroups()));
                    yield new Server(type, buffer, supportedGroups);
                }
            };
        }

        private TlsKeyExchange newClientKeyExchange(TlsContext context) {
            var group = context.remoteKeyExchange()
                    .map(entry -> entry instanceof Server serverKeyExchange ? serverKeyExchange : null)
                    .orElseThrow(() -> new TlsException("Missing remote ECDH key exchange"))
                    .parameters()
                    .orElseThrow(() -> new TlsException("Missing remote ECDH key parameters"))
                    .toGroup(context);
            var keyPair = group.generateLocalKeyPair(context);
            context.localConnectionState()
                    .setPublicKey(keyPair.getPublic())
                    .setPrivateKey(keyPair.getPrivate());
            var publicKey = group.dumpPublicKey(keyPair.getPublic());
            return new Client(type, publicKey);
        }

        private Server newServerKeyExchange(TlsContext context) {
            var supportedEllipticCurve = context.getNegotiatedValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> TlsException.noNegotiatedProperty(TlsProperty.supportedGroups()))
                    .stream()
                    .filter(supportedGroup -> supportedGroup instanceof TlsSupportedEllipticCurve)
                    .map(supportedGroup -> (TlsSupportedEllipticCurve) supportedGroup)
                    .findFirst()
                    .orElseThrow(TlsException::noSupportedEllipticCurve);
            var keyPair = supportedEllipticCurve.generateLocalKeyPair(context);
            context.localConnectionState()
                    .setPublicKey(keyPair.getPublic())
                    .setPrivateKey(keyPair.getPrivate());
            var parameters = supportedEllipticCurve.toParameters();
            var publicKey = supportedEllipticCurve.dumpPublicKey(keyPair.getPublic());
            return new Server(type, parameters, publicKey);
        }
    }
}
