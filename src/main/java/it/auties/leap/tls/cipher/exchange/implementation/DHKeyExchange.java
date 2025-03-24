package it.auties.leap.tls.cipher.exchange.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeFactory;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.group.TlsSupportedFiniteField;
import it.auties.leap.tls.secret.TlsPreMasterSecretGenerator;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.util.Arrays;
import java.util.NoSuchElementException;

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
                throw new TlsException("Cannot parse DH key", exception);
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
                throw new TlsException("Cannot parse DH key", exception);
            }
        }
    }

    private record DHKeyExchangeFactory(TlsKeyExchangeType type) implements TlsKeyExchangeFactory {
        @Override
        public TlsKeyExchange newLocalKeyExchange(TlsContext context) {
            return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
                case CLIENT -> newClientKeyExchange(context);
                case SERVER -> newServerKeyExchange(context);
            };
        }

        private TlsKeyExchange newClientKeyExchange(TlsContext context) {
            var remoteDhKeyExchange = context.remoteKeyExchange()
                    .map(entry -> entry instanceof Server serverKeyExchange ? serverKeyExchange : null)
                    .orElseThrow(() -> new TlsException("Missing remote DH key exchange"));
            for (var group : context.localSupportedGroups()) {
                if (group instanceof TlsSupportedFiniteField finiteField) {
                    if (finiteField.accepts(remoteDhKeyExchange)) {
                        var keyPair = finiteField.generateLocalKeyPair(context);
                        context.setLocalKeyPair(keyPair);
                        var publicKey = (DHPublicKey) keyPair.getPublic();
                        System.out.println("Local public key: " + Arrays.toString(publicKey.getY().toByteArray()));
                        return new Client(type, publicKey.getY().toByteArray(), publicKey.getParams().getP(), publicKey.getParams().getG());
                    }
                }
            }
            throw new TlsException("Unsupported DH group");
        }

        private TlsKeyExchange newServerKeyExchange(TlsContext context) {
            var group = context.localPreferredFiniteField()
                    .orElseThrow(() -> new NoSuchElementException("No supported group is a finite field"));
            var keyPair = group.generateLocalKeyPair(context);
            context.setLocalKeyPair(keyPair);
            var publicKey = (DHPublicKey) keyPair.getPublic();
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

        @Override
        public TlsKeyExchange decodeRemoteKeyExchange(TlsContext context, ByteBuffer buffer) {
            return switch (context.selectedMode().orElseThrow(() -> new TlsException("No mode was selected"))) {
                case SERVER -> {
                    var localPublicKey = context.localKeyPair()
                            .orElseThrow(() -> new TlsException("Missing local key pair"))
                            .getPublic();
                    if(!(localPublicKey instanceof DHPublicKey dhPublicKey)) {
                        throw new TlsException("Unsupported key type");
                    }
                    yield new Client(type, buffer, dhPublicKey.getParams().getP(), dhPublicKey.getParams().getG());
                }
                case CLIENT -> new Server(type, buffer);
            };
        }
    }
}
