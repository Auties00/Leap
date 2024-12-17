package it.auties.leap.socket.layer;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.tls.certificate.TlsCertificatesHandler;
import it.auties.leap.tls.certificate.TlsClientCertificateType;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.wrapper.TlsCipherWrapper;
import it.auties.leap.tls.config.TlsCompression;
import it.auties.leap.tls.config.TlsConfig;
import it.auties.leap.tls.config.TlsIdentifiableUnion;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.engine.TlsEngine;
import it.auties.leap.tls.extension.TlsExtensionsProcessor;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.hash.TlsHandshakeHash;
import it.auties.leap.tls.key.*;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.client.*;
import it.auties.leap.tls.message.server.*;
import it.auties.leap.tls.message.shared.AlertMessage;
import it.auties.leap.tls.message.shared.ApplicationDataMessage;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;

import static it.auties.leap.tls.BufferHelper.*;

public sealed abstract class SocketSecurityLayer implements HttpDecodable {
    final SocketTransmissionLayer<?> transmissionLayer;

    private SocketSecurityLayer(SocketTransmissionLayer<?> transmissionLayer) {
        this.transmissionLayer = transmissionLayer;
    }

    public static SocketSecurityLayer ofPlain(SocketTransmissionLayer<?> transmissionLayer) {
        return new Plain(transmissionLayer);
    }

    public static SocketSecurityLayer ofSecure(SocketTransmissionLayer<?> transmissionLayer, TlsConfig tlsConfig) {
        return new Secure(transmissionLayer, tlsConfig);
    }

    public abstract CompletableFuture<Void> handshake();

    public abstract boolean isSecure();

    public abstract CompletableFuture<Void> write(ByteBuffer buffer);

    public abstract CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead);

    CompletableFuture<ByteBuffer> readPlain(ByteBuffer buffer, boolean lastRead) {
        return transmissionLayer.read(buffer).thenApply(_ -> {
            if (lastRead) {
                buffer.flip();
            }

            return buffer;
        });
    }

    public CompletableFuture<ByteBuffer> readPlainFully(ByteBuffer buffer) {
        return readPlain(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return CompletableFuture.completedFuture(buffer);
        });
    }

    CompletableFuture<Void> writePlain(ByteBuffer buffer) {
        return transmissionLayer.write(buffer);
    }

    @Override
    public CompletableFuture<ByteBuffer> read() {
        var buffer = ByteBuffer.allocate(transmissionLayer.readBufferSize);
        return read(buffer, true);
    }

    @Override
    public CompletableFuture<ByteBuffer> readFully(int length) {
        if (length < 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Cannot read %s bytes from socket: negative length".formatted(length)));
        }

        var buffer = ByteBuffer.allocate(length);
        return readFully(buffer);
    }

    public CompletableFuture<ByteBuffer> readFully(ByteBuffer buffer) {
        return read(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return CompletableFuture.completedFuture(buffer);
        });
    }

    private static final class Plain extends SocketSecurityLayer {
        private Plain(SocketTransmissionLayer<?> channel) {
            super(channel);
        }

        @Override
        public boolean isSecure() {
            return false;
        }

        @Override
        public CompletableFuture<Void> write(ByteBuffer buffer) {
            return writePlain(buffer);
        }

        @Override
        public CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
            return readPlain(buffer, lastRead);
        }

        @Override
        public CompletableFuture<Void> handshake() {
            return CompletableFuture.completedFuture(null);
        }
    }

    private static final class Secure extends SocketSecurityLayer {
        private static final int FRAGMENT_LENGTH = 18432;

        private final TlsConfig tlsConfig;
        private CompletableFuture<Void> sslHandshake;
        private ByteBuffer tlsBuffer;

        private final TlsConfig localConfig;
        private final TlsRandomData localRandomData;
        private final TlsSharedSecret localSessionId;

        private final ByteArrayOutputStream messageDigestBuffer;
        private final CopyOnWriteArrayList<TlsMessage.Type> processedMessageTypes;

        private volatile TlsMode mode;

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
        private volatile List<TlsSignatureAndHashAlgorithm> remoteCertificateAlgorithms;
        private volatile List<String> remoteCertificateAuthorities;

        private volatile TlsKeyExchange remoteKeyParameters;
        private volatile TlsIdentifiableUnion<TlsSignatureAndHashAlgorithm, Integer> remoteKeySignatureAlgorithm;
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

        public Optional<TlsMode> selectedMode() {
            return Optional.ofNullable(mode);
        }

        public void handleMessage(TlsMessage message) {
            if(!message.isSupported(localConfig.version(), mode, message.source(), processedMessageTypes)) {
                throw new TlsException("Unexpected message %s after %s".formatted(message.type(), processedMessageTypes.isEmpty() ? "null " : processedMessageTypes.getLast()));
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
                                throw new TlsException("Local random data mismatch");
                            }

                            if (!Arrays.equals(clientHelloMessage.sessionId().data(), localSessionId.data())) {
                                throw new TlsException("Local session id mismatch");
                            }

                            this.mode = TlsMode.CLIENT;
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
                                throw new TlsException("Local random data mismatch");
                            }

                            if (!Arrays.equals(serverHelloMessage.sessionId().data(), localSessionId.data())) {
                                throw new TlsException("Local session id mismatch");
                            }

                            this.mode = TlsMode.SERVER;
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
                    this.remoteKeyParameters = serverKeyExchangeMessage.keyExchange();
                    this.remoteKeySignatureAlgorithm = serverKeyExchangeMessage.signatureAlgorithm();
                    this.remoteKeySignature = serverKeyExchangeMessage.signature();
                }

                case ServerFinishedMessage serverFinishedMessage -> {
                    if(mode == TlsMode.CLIENT) {
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
                    if(mode == TlsMode.SERVER) {
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
                if(((TlsKeyExchange.Server) remoteKeyParameters) == null) {
                    throw new TlsException("Missing remote key parameters");
                }

                return (TlsKeyExchange.Server) remoteKeyParameters);
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
                throw new TlsException("Cannot generate keypair: a keypair is already linked to this engine");
            }

            var preferredGroup = supportedGroups.isEmpty() ? null : supportedGroups.getFirst();
            if(preferredGroup == null) {
                throw new TlsException("Cannot generate keypair, no supported groups found: make sure that you are not providing an empty list for TlsExtension.supportedGroups(...)");
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

        public void encrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
            if(localCipher == null) {
                throw new TlsException("Cannot encrypt a message before enabling the local cipher");
            }

            localCipher.encrypt(contentType, input, output);
        }

        public void decrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
            if(remoteCipher == null) {
                throw new TlsException("Cannot decrypt a message before enabling the remote cipher");
            }

            remoteCipher.decrypt(contentType, input, output, null);
        }

        public Optional<ByteBuffer> lastBufferedMessage() {
            return bufferedMessages.isEmpty() ? Optional.empty() : Optional.ofNullable(bufferedMessages.poll());
        }

        public void pollBufferedMessage() {
            bufferedMessages.poll();
        }

        private Secure(SocketTransmissionLayer<?> channel, TlsConfig tlsConfig) {
            super(channel);
            this.tlsConfig = tlsConfig;
        }

        @Override
        public boolean isSecure() {
            return true;
        }

        @Override
        public CompletableFuture<Void> handshake() {
            try {
                if (sslHandshake != null) {
                    return sslHandshake;
                }

                synchronized (this) {
                    if (sslHandshake != null) {
                        return sslHandshake;
                    }

                    this.tlsEngine = new TlsEngine(transmissionLayer.address, tlsConfig);
                    this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
                    return this.sslHandshake = sendClientHello()
                            .thenCompose(_ -> continueHandshake());
                }
            }catch (Throwable throwable) {
                return CompletableFuture.failedFuture(throwable);
            }
        }

        private CompletionStage<Void> continueHandshake() {
            return switch (tlsEngine.config().version()) {
                // TODO: Send finished message
                case TLS13 -> sendClientFinish()
                        .thenCompose(_ -> readUntilHandshakeCompleted());

                case TLS12, TLS11 -> readUntilServerDone()
                        .thenCompose(_ -> sendClientCertificate())
                        .thenCompose(_ -> sendClientKeyExchange())
                        .thenCompose(_ -> sendClientCertificateVerify())
                        .thenCompose(_ -> sendClientChangeCipher())
                        .thenCompose(_ -> sendClientFinish())
                        .thenCompose(_ -> readUntilHandshakeCompleted());

                default -> throw new UnsupportedOperationException();
            };
        }

        private CompletableFuture<Void> sendClientHello() {
            var handshakeBuffer = writeBuffer();
            var extensionsConfigurator = new TlsExtensionsProcessor(tlsEngine);
            var helloMessage = new ClientHelloMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL,
                    tlsEngine.localRandomData(),
                    tlsEngine.localSessionId(),
                    tlsEngine.dtlsCookie().orElse(null),
                    tlsEngine.config().ciphers(),
                    tlsEngine.config().compressions(),
                    extensionsConfigurator.extensions(),
                    extensionsConfigurator.extensionsLength()
            );
            var helloBuffer = writeBuffer();
            helloMessage.serializeMessageWithRecord(helloBuffer);
            tlsEngine.updateHandshakeHash(helloBuffer, TlsMessage.messageRecordHeaderLength());
            tlsEngine.digestHandshakeHash();
            System.out.println(HexFormat.of().formatHex(handshakeBuffer.array(), handshakeBuffer.position(), handshakeBuffer.limit()));
            return write(handshakeBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(helloMessage));
        }

        private CompletableFuture<Void> sendClientCertificate() {
            if (!tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CERTIFICATE_REQUEST)) {
                return CompletableFuture.completedFuture(null);
            }

            System.out.println("Sending client certificate");
            var certificatesProvider = tlsEngine.config()
                    .certificatesProvider()
                    .orElse(null);
            if(certificatesProvider == null) {
                return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
            }

            var certificatesMessage = new ClientCertificateMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL,
                    certificatesProvider.getCertificates(transmissionLayer.address)
            );
            var certificatesBuffer = writeBuffer();
            certificatesMessage.serializeMessageWithRecord(certificatesBuffer);
            tlsEngine.updateHandshakeHash(certificatesBuffer, TlsMessage.messageRecordHeaderLength());
            tlsEngine.digestHandshakeHash();
            return write(certificatesBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(certificatesMessage));
        }

        private CompletableFuture<Void> sendClientKeyExchange() {
            System.out.println("Sending client key exchange");
            var cipher = tlsEngine.negotiatedCipher()
                    .orElseThrow(() -> new IllegalStateException("Expected a cipher to be already negotiated"));
            var keyExchangeMessage = new ClientKeyExchangeMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL,
                    parameters
            );
            var keyExchangeBuffer = writeBuffer();
            keyExchangeMessage.serializeMessageWithRecord(keyExchangeBuffer);
            tlsEngine.updateHandshakeHash(keyExchangeBuffer, TlsMessage.messageRecordHeaderLength());
            tlsEngine.digestHandshakeHash();
            return write(keyExchangeBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(keyExchangeMessage));
        }

        private CompletableFuture<Void> sendClientCertificateVerify() {
            if (true) { // !tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CERTIFICATE)
                return CompletableFuture.completedFuture(null);
            }

            System.out.println("Sending client verify");
            var clientVerifyCertificate = new ClientCertificateVerifyMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL
            );
            var clientVerifyBuffer = writeBuffer();
            clientVerifyCertificate.serializeMessageWithRecord(clientVerifyBuffer);
            tlsEngine.updateHandshakeHash(clientVerifyBuffer, TlsMessage.messageRecordHeaderLength());
            tlsEngine.digestHandshakeHash();
            return write(clientVerifyBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(clientVerifyCertificate));
        }

        private CompletableFuture<Void> sendClientChangeCipher() {
            System.out.println("Sending client change cipher");
            var changeCipherSpec = new ClientChangeCipherSpecMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL
            );
            var changeCipherSpecBuffer = writeBuffer();
            changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
            return write(changeCipherSpecBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(changeCipherSpec));
        }

        private CompletableFuture<Void> sendClientFinish() {
            var handshakeHash = tlsEngine.handshakeVerificationData(TlsMessage.Source.LOCAL)
                    .orElseThrow(() -> new TlsException("Missing handshake"));
            var finishedMessage = new ClientFinishedMessage(
                    tlsEngine.config().version(),
                    TlsMessage.Source.LOCAL,
                    handshakeHash
            );
            
            var leftPadding = tlsEngine.explicitNonceLength()
                    .orElseThrow(() -> new InternalError("Missing negotiated cipher"));
            var reservedSpace = TlsMessage.messageRecordHeaderLength() + leftPadding;
            var messagePayloadBuffer = writeBuffer()
                    .position(reservedSpace);
            finishedMessage.serializeMessagePayload(messagePayloadBuffer);
            messagePayloadBuffer.limit(messagePayloadBuffer.position())
                    .position(reservedSpace);

            var encryptedMessagePayloadBuffer = messagePayloadBuffer.duplicate()
                    .limit(messagePayloadBuffer.capacity())
                    .position(reservedSpace);
            tlsEngine.encrypt(
                    TlsMessage.ContentType.HANDSHAKE,
                    messagePayloadBuffer,
                    encryptedMessagePayloadBuffer
            );

            var encryptedMessagePosition = encryptedMessagePayloadBuffer.position() - TlsMessage.messageRecordHeaderLength();
            var encryptedMessageLength = encryptedMessagePayloadBuffer.remaining();
            encryptedMessagePayloadBuffer.position(encryptedMessagePosition);
            writeLittleEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.contentType().id());
            writeLittleEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().major());
            writeLittleEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().minor());
            writeLittleEndianInt16(encryptedMessagePayloadBuffer, encryptedMessageLength);
            encryptedMessagePayloadBuffer.position(encryptedMessagePosition);

            return write(encryptedMessagePayloadBuffer)
                    .thenRun(() -> tlsEngine.handleMessage(finishedMessage));
        }

        private CompletableFuture<Void> readUntilServerDone() {
            if(tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE)) {
                return CompletableFuture.completedFuture(null);
            }

            return readAndHandleMessage()
                    .thenCompose(_ -> readUntilServerDone());
        }

        private CompletableFuture<Void> readUntilHandshakeCompleted() {
            if(tlsEngine.isHandshakeComplete()) {
                return CompletableFuture.completedFuture(null);
            }

            return readAndHandleMessage()
                    .thenCompose(_ -> readUntilHandshakeCompleted());
        }

        @Override
        public CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
            if(buffer == null || !buffer.hasRemaining()) {
                return CompletableFuture.completedFuture(buffer);
            }

            if (!tlsEngine.isRemoteCipherEnabled()) {
                return readPlain(buffer, lastRead);
            }

            var message = tlsEngine.lastBufferedMessage()
                    .orElse(null);
            if (message != null) {
                while (buffer.hasRemaining() && message.hasRemaining()) {
                    buffer.put(message.get());
                }
                if(!message.hasRemaining()) {
                    tlsEngine.pollBufferedMessage();
                }
                buffer.flip();
                return CompletableFuture.completedFuture(buffer);
            }else {
                return readAndHandleMessage()
                        .thenCompose(_ -> read(buffer, lastRead));
            }
        }

        @Override
        public CompletableFuture<Void> write(ByteBuffer buffer) {
            if (buffer == null || !buffer.hasRemaining()) {
                return CompletableFuture.completedFuture(null);
            }

            if (!tlsEngine.isLocalCipherEnabled()) {
                return writePlain(buffer);
            }

            // Check that we are not using the same buffer as the tlsBuffer
            assertNotEquals(buffer, tlsBuffer);

            // Serialize the message
            var leftPadding = tlsEngine.explicitNonceLength()
                    .orElseThrow(() -> new InternalError("Missing negotiated cipher"));
            var plaintext = writeBuffer()
                    .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
            var dataMessage = new ApplicationDataMessage(
                    tlsConfig.version(),
                    TlsMessage.Source.LOCAL,
                    buffer
            );
            dataMessage.serializeMessage(plaintext);

            // Encrypt the message
            var encrypted = plaintext.duplicate()
                    .limit(plaintext.capacity())
                    .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
            tlsEngine.encrypt(
                    TlsMessage.ContentType.APPLICATION_DATA,
                    plaintext,
                    encrypted
            );
            ApplicationDataMessage.serializeInline(
                    tlsEngine.config().version(),
                    encrypted
            );

            // Write the message
            return writePlain(encrypted);
        }

        private CompletableFuture<Void> readAndHandleMessage() {
            return readPlain(readBuffer(TlsMessage.Metadata.length()), true)
                    .thenApply(TlsMessage.Metadata::of)
                    .thenCompose(this::decodeMessage);
        }

        private CompletableFuture<Void> decodeMessage(TlsMessage.Metadata metadata) {
            var buffer = readBuffer(metadata.messageLength());
            return readPlainFully(buffer).thenAccept(messageBuffer -> {
                var cipher = tlsEngine.negotiatedCipher()
                        .orElse(null);
                if (tlsEngine.isRemoteCipherEnabled()) {
                    var plainBuffer = plainBuffer();
                    tlsEngine.decrypt(metadata.contentType(), messageBuffer, plainBuffer);
                    metadata.setMessageLength(plainBuffer.remaining());
                    var message = TlsMessage.ofServer(cipher, plainBuffer, metadata);
                    tlsEngine.handleMessage(message);
                } else {
                    if (!tlsEngine.isHandshakeComplete()) {
                        tlsEngine.updateHandshakeHash(messageBuffer, 0); // The header isn't included at this point
                    }
                    var message = TlsMessage.ofServer(cipher, messageBuffer, metadata);
                    tlsEngine.handleMessage(message);
                    if (!tlsEngine.isHandshakeComplete()) {
                        tlsEngine.digestHandshakeHash();
                    }
                }
            });
        }

        private ByteBuffer plainBuffer() {
            return tlsBuffer.duplicate()
                    .position(0)
                    .limit(tlsBuffer.capacity());
        }

        private ByteBuffer writeBuffer() {
            return tlsBuffer.position(0)
                    .limit(tlsBuffer.capacity());
        }

        private ByteBuffer readBuffer(int length) {
            return tlsBuffer.position(0)
                    .limit(length);
        }
    }
}
