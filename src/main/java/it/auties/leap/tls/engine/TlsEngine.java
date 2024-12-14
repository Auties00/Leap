package it.auties.leap.tls.engine;

import it.auties.leap.tls.*;
import it.auties.leap.tls.crypto.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.crypto.cipher.wrap.TlsCipherWrapper;
import it.auties.leap.tls.crypto.hash.TlsHandshakeHash;
import it.auties.leap.tls.crypto.key.*;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessage.ContentType;
import it.auties.leap.tls.message.client.ClientCertificateMessage;
import it.auties.leap.tls.message.client.ClientFinishedMessage;
import it.auties.leap.tls.message.client.ClientHelloMessage;
import it.auties.leap.tls.message.client.ClientKeyExchangeMessage;
import it.auties.leap.tls.message.server.*;
import it.auties.leap.tls.message.shared.AlertMessage;
import it.auties.leap.tls.message.shared.ApplicationDataMessage;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

// TODO: Inline this class once it's organized well in SocketSecurityLayer
public class TlsEngine {
    private final TlsConfig localConfig;
    private final TlsRandomData localRandomData;
    private final TlsSharedSecret localSessionId;

    private final ByteArrayOutputStream messageDigestBuffer;
    private final CopyOnWriteArrayList<TlsMessage.Type> processedMessageTypes;

    private volatile TlsEngineMode mode;

    private final InetSocketAddress remoteAddress;
    private volatile TlsRandomData remoteRandomData;
    private volatile TlsSharedSecret remoteSessionId;

    private volatile TlsCipher negotiatedCipher;
    private volatile TlsHandshakeHash handshakeHash;
    private volatile TlsCompression negotiatedCompression;

    private volatile TlsCipherWrapper localCipher;
    private volatile TlsCipherWrapper remoteCipher;

    private volatile TlsExchangeAuthenticator localAuthenticator;
    private volatile TlsExchangeAuthenticator remoteAuthenticator;

    private volatile List<TlsClientCertificateType> remoteCertificateTypes;
    private volatile List<TlsSignatureAlgorithm> remoteCertificateAlgorithms;
    private volatile List<String> remoteCertificateAuthorities;

    private volatile TlsServerKey remoteKeyParameters;
    private volatile TlsSignatureAlgorithm remoteKeySignatureAlgorithm;
    private volatile byte[] remoteKeySignature;

    private volatile TlsKeyPair localKeyPair;

    private volatile TlsCookie dtlsCookie;

    private volatile List<TlsSupportedGroup> supportedGroups;
    private volatile boolean extendedMasterSecret;

    private volatile TlsSessionKeys sessionKeys;
    private final Queue<ByteBuffer> bufferedMessages;

    public TlsEngine(InetSocketAddress address, TlsConfig config) {
        this.remoteAddress = address;
        this.localConfig = config;
        this.localRandomData = TlsRandomData.random();
        this.localSessionId = TlsSharedSecret.random();
        this.processedMessageTypes = new CopyOnWriteArrayList<>();
        this.dtlsCookie = switch (config.version().protocol()) {
            case TCP -> null;
            case UDP -> TlsCookie.empty();
        };
        this.supportedGroups = TlsSupportedGroup.supportedGroups();
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
    }

    public TlsConfig config() {
        return localConfig;
    }

    public Optional<TlsCipher> negotiatedCipher() {
        return Optional.ofNullable(negotiatedCipher);
    }

    public Optional<TlsEngineMode> selectedMode() {
        return Optional.ofNullable(mode);
    }

    public void handleMessage(TlsMessage message) {
        if(!message.isSupported(localConfig.version(), mode, message.source(), processedMessageTypes)) {
            throw new TlsSpecificationException("Unexpected message %s after %s".formatted(message.type(), processedMessageTypes.isEmpty() ? "null " : processedMessageTypes.getLast()));
        }

        processedMessageTypes.add(message.type());
        System.out.println("Handling " + message.getClass().getName());
        switch (message) {
            case ServerHelloRequestMessage _ -> {
                // This message will be ignored by the client if the client is currently negotiating a session.
                // TODO: Implement logic
            }

            case ClientHelloMessage clientHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(clientHelloMessage.randomData().data(), localRandomData.data())) {
                            throw new TlsSpecificationException("Local random data mismatch");
                        }

                        if (!Arrays.equals(clientHelloMessage.sessionId().data(), localSessionId.data())) {
                            throw new TlsSpecificationException("Local session id mismatch");
                        }

                        this.mode = TlsEngineMode.CLIENT;
                    }
                    case REMOTE -> {
                        this.remoteRandomData = clientHelloMessage.randomData();
                        this.remoteSessionId = clientHelloMessage.sessionId();
                    }
                }
            }

            case ServerHelloMessage serverHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(serverHelloMessage.randomData().data(), localRandomData.data())) {
                            throw new TlsSpecificationException("Local random data mismatch");
                        }

                        if (!Arrays.equals(serverHelloMessage.sessionId().data(), localSessionId.data())) {
                            throw new TlsSpecificationException("Local session id mismatch");
                        }

                        this.mode = TlsEngineMode.SERVER;
                    }
                    case REMOTE -> {
                        this.remoteRandomData = serverHelloMessage.randomData();
                        this.remoteSessionId = serverHelloMessage.sessionId();
                    }
                }
                System.out.println("Selected cipher: " + serverHelloMessage.cipher());
                this.negotiatedCipher = serverHelloMessage.cipher();
                this.handshakeHash = TlsHandshakeHash.of(localConfig.version(), negotiatedCipher.hash());
                this.negotiatedCompression = serverHelloMessage.compression();
            }

            case ServerCertificateMessage certificateMessage -> {
                var certificates = certificateMessage.certificates();
                localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, TlsCertificatesHandler.Source.SERVER);
            }

            case ServerCertificateRequestMessage certificateRequestMessage -> {
                this.remoteCertificateTypes = certificateRequestMessage.types();
                this.remoteCertificateAlgorithms = certificateRequestMessage.algorithms();
                this.remoteCertificateAuthorities = certificateRequestMessage.authorities();
            }

            case ServerKeyExchangeMessage serverKeyExchangeMessage -> {
                this.remoteKeyParameters = serverKeyExchangeMessage.parameters();
                this.remoteKeySignatureAlgorithm = serverKeyExchangeMessage.signatureAlgorithm();
                this.remoteKeySignature = serverKeyExchangeMessage.signature();
            }

            case ServerFinishedMessage serverFinishedMessage -> {
                if(mode == TlsEngineMode.CLIENT) {
                    // TODO: Validate
                }
            }

            case ClientKeyExchangeMessage _ -> {
                var preMasterSecret = createPreMasterSecret();
                var masterSecret = TlsMasterSecretKey.of(
                        mode,
                        localConfig.version(),
                        negotiatedCipher,
                        preMasterSecret,
                        extendedMasterSecret ? handshakeHash().orElse(null) : null,
                        localRandomData,
                        remoteRandomData
                );
                this.sessionKeys = TlsSessionKeys.of(
                        mode,
                        localConfig.version(),
                        negotiatedCipher,
                        masterSecret,
                        localRandomData,
                        remoteRandomData
                );
                this.localAuthenticator = TlsExchangeAuthenticator.of(
                        localConfig.version(),
                        negotiatedCipher,
                        sessionKeys.localMacKey()
                );
                this.remoteAuthenticator = TlsExchangeAuthenticator.of(
                        localConfig.version(),
                        negotiatedCipher,
                        sessionKeys.remoteMacKey()
                );
                this.localCipher = TlsCipherWrapper.of(
                        localConfig.version(),
                        negotiatedCipher,
                        localAuthenticator,
                        sessionKeys,
                        mode
                );
                this.remoteCipher = TlsCipherWrapper.of(
                        localConfig.version(),
                        negotiatedCipher,
                        remoteAuthenticator,
                        sessionKeys,
                        mode
                );
            }

            case ClientCertificateMessage certificateMessage -> {
                var certificates = certificateMessage.certificates();
                localConfig.certificatesHandler()
                        .accept(remoteAddress, certificates, TlsCertificatesHandler.Source.CLIENT);
            }

            case ClientFinishedMessage clientFinishedMessage -> {
                if(mode == TlsEngineMode.SERVER) {
                    // TODO: Validate
                }
            }

            case ApplicationDataMessage applicationDataMessage -> {
                if(message.source() == TlsMessage.Source.REMOTE) {
                    bufferedMessages.add(applicationDataMessage.message());
                }
            }

            case AlertMessage alertMessage -> throw new IllegalArgumentException("Received alert: " + alertMessage);

            default -> {}
        }
    }

    private byte[] createPreMasterSecret() {
        try {
            if(remoteKeyParameters == null) {
                throw new TlsSpecificationException("Missing remote key parameters");
            }

            switch (remoteKeyParameters) {
                case TlsServerKey.DHE dhe -> {
                    var localKeyPair = localKeyPair()
                            .orElseThrow(() -> new TlsSpecificationException("Cannot use local key pair as it wasn't generated"));
                    var keyAgreement = KeyAgreement.getInstance("DH");
                    keyAgreement.init(localKeyPair.keyPair().getPrivate());
                    var keyFactory = KeyFactory.getInstance("DH");
                    var dhPubKeySpecs = new DHPublicKeySpec(
                            convertKeyToJca(dhe.y()),
                            convertKeyToJca(dhe.p()),
                            convertKeyToJca(dhe.g())
                    );
                    var serverPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPubKeySpecs);
                    keyAgreement.doPhase(serverPublicKey, true);
                    return keyAgreement.generateSecret();
                }

                case TlsServerKey.ECCPWD eccpwd -> {

                }

                case TlsServerKey.ECDHE ecdhe -> {
                    switch (ecdhe.parameters()) {
                        case TlsServerKey.ECDHE.ECDHEParameters.ExplicitChar2 explicitChar2 -> {

                        }
                        case TlsServerKey.ECDHE.ECDHEParameters.ExplicitPrime explicitPrime -> {

                        }
                        case TlsServerKey.ECDHE.ECDHEParameters.NamedCurve namedCurve -> {
                            var localKeyPair = localKeyPair()
                                    .orElseThrow(() -> new TlsSpecificationException("Cannot use local key pair as it wasn't generated"));
                            switch (namedCurve.group()) {
                                case SECT163K1 -> {
                                }
                                case SECT163R1 -> {
                                }
                                case SECT163R2 -> {
                                }
                                case SECT193R1 -> {
                                }
                                case SECT193R2 -> {
                                }
                                case SECT233K1 -> {
                                }
                                case SECT233R1 -> {
                                }
                                case SECT239K1 -> {
                                }
                                case SECT283K1 -> {
                                }
                                case SECT283R1 -> {
                                }
                                case SECT409K1 -> {
                                }
                                case SECT409R1 -> {
                                }
                                case SECT571K1 -> {
                                }
                                case SECT571R1 -> {
                                }
                                case SECP160K1 -> {
                                }
                                case SECP160R1 -> {
                                }
                                case SECP160R2 -> {
                                }
                                case SECP192K1 -> {
                                }
                                case SECP192R1 -> {
                                }
                                case SECP224K1 -> {
                                }
                                case SECP224R1 -> {
                                }
                                case SECP256K1 -> {
                                }
                                case SECP256R1 -> {
                                }
                                case SECP384R1 -> {
                                }
                                case SECP521R1 -> {
                                }
                                case BRAINPOOLP256R1 -> {
                                }
                                case BRAINPOOLP384R1 -> {
                                }
                                case BRAINPOOLP512R1 -> {
                                }
                                case X25519 -> {
                                    var keyAgreement = KeyAgreement.getInstance("XDH");
                                    keyAgreement.init(localKeyPair.keyPair().getPrivate());
                                    var keyFactory = KeyFactory.getInstance("X25519");
                                    var xecPublicKeySpec = new XECPublicKeySpec(NamedParameterSpec.X25519, convertKeyToJca(ecdhe.rawPublicKey()));
                                    var serverPublicKey = (XECPublicKey) keyFactory.generatePublic(xecPublicKeySpec);
                                    keyAgreement.doPhase(serverPublicKey, true);
                                    return keyAgreement.generateSecret();
                                }
                                case X448 -> {
                                }
                                case BRAINPOOLP256R1TLS13 -> {
                                }
                                case BRAINPOOLP384R1TLS13 -> {
                                }
                                case BRAINPOOLP512R1TLS13 -> {
                                }
                                case GC256A -> {
                                }
                                case GC256B -> {
                                }
                                case GC256C -> {
                                }
                                case GC256D -> {
                                }
                                case GC512A -> {
                                }
                                case GC512B -> {
                                }
                                case GC512C -> {
                                }
                                case CURVESM2 -> {
                                }
                                case FFDHE2048 -> {
                                }
                                case FFDHE3072 -> {
                                }
                                case FFDHE4096 -> {
                                }
                                case FFDHE6144 -> {
                                }
                                case FFDHE8192 -> {
                                }
                                case MLKEM512 -> {
                                }
                                case MLKEM768 -> {
                                }
                                case MLKEM1024 -> {
                                }
                                case SECP256R1MLKEM768 -> {
                                }
                                case X25519MLKEM768 -> {
                                }
                                case ARBITRARY_EXPLICIT_PRIME_CURVES -> {
                                }
                                case ARBITRARY_EXPLICIT_CHAR2_CURVES -> {
                                }
                            }
                        }
                    }
                }

                case TlsServerKey.GOSTR gostr -> {
                }

                case TlsServerKey.PSK psk -> {
                }

                case TlsServerKey.SRP srp -> {
                }
            }
            return null;
        }catch (GeneralSecurityException exception) {
            exception.printStackTrace();
            return null;
        }
    }

    private static BigInteger convertKeyToJca(byte[] arr) {
        var result = new byte[32];
        var padding = result.length - arr.length;
        for(var i = 0; i < arr.length; i++) {
            result[i + padding] = arr[arr.length - (i + 1)];
        }

        return new BigInteger(result);
    }

    public boolean isHandshakeComplete() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_FINISHED);
    }

    public boolean isLocalCipherEnabled() {
        return switch (mode) {
            case CLIENT -> hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_FINISHED);
            case SERVER -> hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE);
            case null -> false;
        };
    }

    public boolean isRemoteCipherEnabled() {
        return switch (mode) {
            case CLIENT -> hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE);
            case SERVER -> hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_FINISHED);
            case null -> false;
        };
    }

    public boolean hasReceivedFragments() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.APPLICATION_DATA);
    }

    public boolean hasProcessedHandshakeMessage(TlsMessage.Type type) {
        return processedMessageTypes.contains(type);
    }

    public TlsRandomData localRandomData() {
        return localRandomData;
    }

    public TlsSharedSecret localSessionId() {
        return localSessionId;
    }

    public Optional<InetSocketAddress> remoteAddress() {
        return Optional.ofNullable(remoteAddress);
    }

    public TlsKeyPair createKeyPair() {
        if(localKeyPair != null) {
            throw new TlsSpecificationException("Cannot generate keypair: a keypair is already linked to this engine");
        }

        var preferredGroup = supportedGroups.isEmpty() ? null : supportedGroups.getFirst();
        if(preferredGroup == null) {
            throw new TlsSpecificationException("Cannot generate keypair, no supported groups found: make sure that you are not providing an empty list for TlsExtension.supportedGroups(...)");
        }

        this.localKeyPair = TlsKeyPair.random(supportedGroups.getFirst());
        return localKeyPair;
    }

    public Optional<TlsKeyPair> localKeyPair() {
        return Optional.ofNullable(localKeyPair);
    }

    public Optional<TlsCookie> dtlsCookie() {
        return Optional.ofNullable(dtlsCookie);
    }

    public void setSupportedGroups(List<TlsSupportedGroup> supportedGroups) {
        this.supportedGroups = supportedGroups;
    }

    public void enableExtendedMasterSecret() {
        this.extendedMasterSecret = true;
    }

    public Optional<byte[]> handshakeHash() {
        if(handshakeHash == null) {
            return Optional.empty();
        }else {
            return Optional.ofNullable(handshakeHash.digest());
        }
    }

    public Optional<byte[]> handshakeVerificationData(TlsMessage.Source source) {
        if(handshakeHash == null) {
            return Optional.empty();
        }else {
            return Optional.ofNullable(handshakeHash.finish(this, source));
        }
    }

    public void updateHandshakeHash(ByteBuffer buffer, int offset) {
        var length = buffer.remaining() - offset;
        for(var i = 0; i < length; i++) {
            messageDigestBuffer.write(buffer.get(buffer.position() + offset + i));
        }
    }

    public void digestHandshakeHash() {
        if(handshakeHash != null) {
            handshakeHash.update(messageDigestBuffer.toByteArray());
            messageDigestBuffer.reset();
        }
    }

    public Optional<TlsSessionKeys> sessionKeys() {
        return Optional.ofNullable(sessionKeys);
    }

    public OptionalInt explicitNonceLength() {
        return localCipher != null ? OptionalInt.of(localCipher.nonceLength()) : OptionalInt.empty();
    }

    public void encrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        if(localCipher == null) {
            throw new TlsSpecificationException("Cannot encrypt a message before enabling the local cipher");
        }

        localCipher.encrypt(contentType, input, output);
    }

    public void decrypt(ContentType contentType, ByteBuffer input, ByteBuffer output) {
        if(remoteCipher == null) {
            throw new TlsSpecificationException("Cannot decrypt a message before enabling the remote cipher");
        }

       remoteCipher.decrypt(contentType, input, output, null);
    }

    public Optional<ByteBuffer> lastBufferedMessage() {
        return bufferedMessages.isEmpty() ? Optional.empty() : Optional.ofNullable(bufferedMessages.poll());
    }

    public void pollBufferedMessage() {
        bufferedMessages.poll();
    }
}
