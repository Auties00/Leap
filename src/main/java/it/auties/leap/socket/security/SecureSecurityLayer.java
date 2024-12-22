package it.auties.leap.socket.security;

import it.auties.leap.socket.transmission.SocketTransmissionLayer;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.mode.TlsCipherMode;
import it.auties.leap.tls.config.TlsCompression;
import it.auties.leap.tls.config.TlsConfig;
import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.hash.TlsExchangeAuthenticator;
import it.auties.leap.tls.hash.TlsHandshakeHash;
import it.auties.leap.tls.hash.TlsHmac;
import it.auties.leap.tls.key.*;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.client.*;
import it.auties.leap.tls.message.server.*;
import it.auties.leap.tls.message.shared.AlertMessage;
import it.auties.leap.tls.message.shared.ApplicationDataMessage;
import it.auties.leap.tls.signature.TlsSignatureAndHashAlgorithm;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;

import static it.auties.leap.tls.util.BufferHelper.*;

final class SecureSecurityLayer extends SocketSecurityLayer {
    private static final int FRAGMENT_LENGTH = 18432;

    private final TlsConfig tlsConfig;
    private CompletableFuture<Void> sslHandshake;
    private ByteBuffer tlsBuffer;

    private final TlsRandomData clientRandomData;
    private final TlsSharedSecret clientSessionId;

    private final ByteArrayOutputStream messageDigestBuffer;
    private final CopyOnWriteArrayList<TlsMessage.Type> processedMessageTypes;

    private volatile TlsRandomData serverRandomData;
    private volatile TlsSharedSecret serverSessionId;

    private volatile TlsCipher negotiatedCipher;
    private volatile TlsHandshakeHash handshakeHash;
    private volatile TlsCompression negotiatedCompression;
    private volatile TlsSignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm;

    private volatile TlsCipherMode clientCipher;
    private volatile TlsCipherMode serverCipher;
    private volatile TlsExchangeAuthenticator clientAuth;
    private volatile TlsExchangeAuthenticator serverAuth;

    private volatile TlsServerKeyExchange serverKeyExchange;
    private volatile byte[] remoteKeySignature;


    private final TlsCookie clientDtlsCookie;

    private volatile boolean extendedMasterSecret;

    private volatile TlsSessionKeys sessionKeys;
    private final Queue<ByteBuffer> bufferedMessages;

    SecureSecurityLayer(SocketTransmissionLayer<?> channel, TlsConfig tlsConfig) {
        super(channel);
        this.tlsConfig = tlsConfig;
        this.clientRandomData = TlsRandomData.random();
        this.clientSessionId = TlsSharedSecret.random();
        this.processedMessageTypes = new CopyOnWriteArrayList<>();
        this.clientDtlsCookie = switch (tlsConfig.version().protocol()) {
            case TCP -> null;
            case UDP -> TlsCookie.empty();
        };
        this.messageDigestBuffer = new ByteArrayOutputStream(); // TODO: Calculate optimal space
        this.bufferedMessages = new LinkedList<>();
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

                this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
                return this.sslHandshake = sendClientHello()
                        .thenCompose(_ -> continueHandshake());
            }
        } catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private CompletionStage<Void> continueHandshake() {
        return switch (tlsConfig.version()) {
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

        var compatibleExtensions = tlsConfig.extensions()
                .stream()
                .filter(extension -> extension.versions().contains(tlsConfig.version()))
                .toList();

        // Make sure there are no conflicts
        var dependenciesTree = new HashMap<Class<? extends TlsExtension>, TlsExtension.Model.Dependencies>();
        var seen = new HashSet<Class<? extends TlsExtension>>();
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsExtension.Implementation implementationExtension -> {
                    if (!seen.add(implementationExtension.getClass())) {
                        throw new IllegalArgumentException("Extension with type %s conflicts with previously defined extension".formatted(extension.getClass().getName()));
                    }

                    dependenciesTree.put(implementationExtension.getClass(), TlsExtension.Model.Dependencies.none());
                }
                case TlsExtension.Model modelExtension -> {
                    if (!seen.add(modelExtension.getClass())) {
                        throw new IllegalArgumentException("Model with type %s conflicts with previously defined model".formatted(extension.getClass().getName()));
                    }

                    var concreteType = modelExtension.toConcreteType(TlsMode.CLIENT);
                    if (!seen.add(concreteType)) {
                        throw new IllegalArgumentException("Extension with type %s, produced by a model with type %s, conflicts with previously defined extension".formatted(extension.getClass().getName(), concreteType.getName()));
                    }

                    dependenciesTree.put(modelExtension.getClass(), modelExtension.dependencies());
                }
            }
        }

        // Allocate the rounds and fill them
        var rounds = new ArrayList<List<TlsExtension>>();
        rounds.addFirst(new ArrayList<>()); // Allocate the first round
        rounds.addLast(new ArrayList<>()); // Allocate the last round
        for (var extension : compatibleExtensions) {
            switch (extension) {
                case TlsExtension.Implementation implementationExtension -> {
                    // Concrete extensions don't have any dependencies, so we can always process them at the beginning
                    var firstRound = rounds.getFirst();
                    firstRound.add(implementationExtension);
                }
                case TlsExtension.Model modelExtension -> {
                    switch (modelExtension.dependencies()) {
                        // If no dependencies are needed, we can process this extension at the beginning
                        case TlsExtension.Model.Dependencies.None _ -> {
                            var firstRound = rounds.getFirst();
                            firstRound.add(modelExtension);
                        }

                        // If some dependencies are needed to process this extension, calculate after how many rounds it should be processed
                        case TlsExtension.Model.Dependencies.Some some -> {
                            var roundIndex = getRoundIndex(dependenciesTree, rounds.size(), some);
                            var existingRound = rounds.get(roundIndex);
                            if (existingRound != null) {
                                existingRound.add(modelExtension);
                            } else {
                                var newRound = new ArrayList<TlsExtension>();
                                newRound.add(modelExtension);
                                rounds.set(roundIndex, newRound);
                            }
                        }

                        // If all dependencies are needed to process this extension, we can this process this extension at the end
                        case TlsExtension.Model.Dependencies.All _ -> {
                            var lastRound = rounds.getLast();
                            lastRound.addFirst(modelExtension);
                        }
                    }
                }
            }
        }

        // Actually process the annotations
        var context = TlsExtension.Model.Context.of(transmissionLayer.address().orElse(null), tlsConfig, TlsMode.CLIENT);
        for (var round : rounds) {
            for (var extension : round) {
                switch (extension) {
                    case TlsExtension.Implementation implementation -> context.putExtension(implementation);
                    case TlsExtension.Model model -> {
                        var result = model.newInstance(context);
                        result.ifPresent(context::putExtension);
                    }
                }
            }
        }

        var helloMessage = new ClientHelloMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                clientRandomData,
                clientSessionId,
                clientDtlsCookie,
                tlsConfig.ciphers().stream().map(TlsCipher::id).toList(),
                tlsConfig.compressions().stream().map(TlsCompression::id).toList(),
                context.processedExtensions(),
                context.processedExtensionsLength()
        );
        var helloBuffer = writeBuffer();
        helloMessage.serializeMessageWithRecord(helloBuffer);
        updateHandshakeHash(helloBuffer, TlsMessage.messageRecordHeaderLength());
        digestHandshakeHash();
        System.out.println(HexFormat.of().formatHex(handshakeBuffer.array(), handshakeBuffer.position(), handshakeBuffer.limit()));
        return write(handshakeBuffer)
                .thenRun(() -> handleMessage(helloMessage));
    }

    private static int getRoundIndex(Map<Class<? extends TlsExtension>, TlsExtension.Model.Dependencies> dependenciesTree, int rounds, TlsExtension.Model.Dependencies.Some some) {
        var roundIndex = 0;
        for (var dependency : some.includedTypes()) {
            var match = dependenciesTree.get(dependency);
            switch (match) {
                // All dependencies are linked to this match: we must process this extension as last
                case TlsExtension.Model.Dependencies.All _ -> {
                    return rounds - 1; // No need to process further, this is already the max value we can find
                }

                // Some dependencies are linked to this match: recursively compute the depth
                case TlsExtension.Model.Dependencies.Some innerSome ->
                        roundIndex = Math.max(roundIndex, getRoundIndex(dependenciesTree, rounds, innerSome) + 1);

                // No dependencies are linked to this match: nothing to add to our dependencies processing queue
                case TlsExtension.Model.Dependencies.None _ -> {
                }

                // No match exists in our dependency tree
                case null -> {
                }
            }
        }
        return roundIndex;
    }

    private CompletableFuture<Void> sendClientCertificate() {
        if (!hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CERTIFICATE_REQUEST)) {
            return CompletableFuture.completedFuture(null);
        }

        System.out.println("Sending client certificate");
        var certificatesProvider = tlsConfig
                .certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var certificatesMessage = new ClientCertificateMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                certificatesProvider.getCertificates(transmissionLayer.address().orElse(null))
        );
        var certificatesBuffer = writeBuffer();
        certificatesMessage.serializeMessageWithRecord(certificatesBuffer);
        updateHandshakeHash(certificatesBuffer, TlsMessage.messageRecordHeaderLength());
        digestHandshakeHash();
        return write(certificatesBuffer)
                .thenRun(() -> handleMessage(certificatesMessage));
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        System.out.println("Sending client key exchange");
        if (negotiatedCipher == null) {
            throw new IllegalStateException("Expected a cipher to be already negotiated");
        }

        var keyExchangeMessage = new ClientKeyExchangeMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                null // TODO
        );
        var keyExchangeBuffer = writeBuffer();
        keyExchangeMessage.serializeMessageWithRecord(keyExchangeBuffer);
        updateHandshakeHash(keyExchangeBuffer, TlsMessage.messageRecordHeaderLength());
        digestHandshakeHash();
        return write(keyExchangeBuffer)
                .thenRun(() -> handleMessage(keyExchangeMessage));
    }

    private CompletableFuture<Void> sendClientCertificateVerify() {
        if (true) { // !hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CERTIFICATE)
            return CompletableFuture.completedFuture(null);
        }

        System.out.println("Sending client verify");
        var clientVerifyCertificate = new ClientCertificateVerifyMessage(
                tlsConfig.version(),
                TlsSource.LOCAL
        );
        var clientVerifyBuffer = writeBuffer();
        clientVerifyCertificate.serializeMessageWithRecord(clientVerifyBuffer);
        updateHandshakeHash(clientVerifyBuffer, TlsMessage.messageRecordHeaderLength());
        digestHandshakeHash();
        return write(clientVerifyBuffer)
                .thenRun(() -> handleMessage(clientVerifyCertificate));
    }

    private CompletableFuture<Void> sendClientChangeCipher() {
        System.out.println("Sending client change cipher");
        var changeCipherSpec = new ClientChangeCipherSpecMessage(
                tlsConfig.version(),
                TlsSource.LOCAL
        );
        var changeCipherSpecBuffer = writeBuffer();
        changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
        return write(changeCipherSpecBuffer)
                .thenRun(() -> handleMessage(changeCipherSpec));
    }

    private CompletableFuture<Void> sendClientFinish() {
        var handshakeHash = handshakeVerificationData()
                .orElseThrow(() -> new TlsException("Missing handshake"));
        var finishedMessage = new ClientFinishedMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                handshakeHash
        );

        var leftPadding = explicitNonceLength()
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
        encrypt(
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
                .thenRun(() -> handleMessage(finishedMessage));
    }

    private CompletableFuture<Void> readUntilServerDone() {
        if (hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE)) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilServerDone());
    }

    private CompletableFuture<Void> readUntilHandshakeCompleted() {
        if (isHandshakeComplete()) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilHandshakeCompleted());
    }

    @Override
    public CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(buffer);
        }

        if (!isRemoteCipherEnabled()) {
            return readPlain(buffer, lastRead);
        }

        var message = lastBufferedMessage()
                .orElse(null);
        if (message != null) {
            while (buffer.hasRemaining() && message.hasRemaining()) {
                buffer.put(message.get());
            }
            if (!message.hasRemaining()) {
                pollBufferedMessage();
            }
            buffer.flip();
            return CompletableFuture.completedFuture(buffer);
        } else {
            return readAndHandleMessage()
                    .thenCompose(_ -> read(buffer, lastRead));
        }
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        if (!isLocalCipherEnabled()) {
            return writePlain(buffer);
        }

        // Check that we are not using the same buffer as the tlsBuffer
        assertNotEquals(buffer, tlsBuffer);

        // Serialize the message
        var leftPadding = explicitNonceLength()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"));
        var plaintext = writeBuffer()
                .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
        var dataMessage = new ApplicationDataMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                buffer
        );
        dataMessage.serializeMessage(plaintext);

        // Encrypt the message
        var encrypted = plaintext.duplicate()
                .limit(plaintext.capacity())
                .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
        encrypt(
                TlsMessage.ContentType.APPLICATION_DATA,
                plaintext,
                encrypted
        );
        ApplicationDataMessage.serializeInline(
                tlsConfig.version(),
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
            if (isRemoteCipherEnabled()) {
                var plainBuffer = plainBuffer();
                decrypt(metadata.contentType(), messageBuffer, plainBuffer);
                metadata.setMessageLength(plainBuffer.remaining());
                var message = TlsMessage.ofServer(negotiatedCipher, tlsConfig.extensionDecoders(), plainBuffer, metadata);
                handleMessage(message);
            } else {
                if (!isHandshakeComplete()) {
                    updateHandshakeHash(messageBuffer, 0); // The header isn't included at this point
                }
                var message = TlsMessage.ofServer(negotiatedCipher, tlsConfig.extensionDecoders(), messageBuffer, metadata);
                handleMessage(message);
                if (!isHandshakeComplete()) {
                    digestHandshakeHash();
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

    private void handleMessage(TlsMessage message) {
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
                        if (!Arrays.equals(clientHelloMessage.randomData().data(), clientRandomData.data())) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(clientHelloMessage.sessionId().data(), clientSessionId.data())) {
                            throw new TlsException("Local session id mismatch");
                        }
                    }
                    case REMOTE -> {
                        this.serverRandomData = clientHelloMessage.randomData();
                        this.serverSessionId = clientHelloMessage.sessionId();
                    }
                }
            }

            case ServerHelloMessage serverHelloMessage -> {
                switch (message.source()) {
                    case LOCAL -> {
                        if (!Arrays.equals(serverHelloMessage.randomData().data(), clientRandomData.data())) {
                            throw new TlsException("Local random data mismatch");
                        }

                        if (!Arrays.equals(serverHelloMessage.sessionId().data(), clientSessionId.data())) {
                            throw new TlsException("Local session id mismatch");
                        }
                    }
                    case REMOTE -> {
                        this.serverRandomData = serverHelloMessage.randomData();
                        this.serverSessionId = serverHelloMessage.sessionId();
                    }
                }
                System.out.println("Selected cipher: " + serverHelloMessage.cipher());
                this.negotiatedCipher = tlsConfig.ciphers()
                        .stream()
                        .filter(entry -> entry.id() == serverHelloMessage.cipher())
                        .findFirst()
                        .orElseThrow(() -> new TlsException("Server selected an unknown cipher"));
                this.handshakeHash = TlsHandshakeHash.of(tlsConfig.version(), negotiatedCipher.hashSupplier());
                this.negotiatedCompression = tlsConfig.compressions()
                        .stream()
                        .filter(entry -> entry.id() == serverHelloMessage.compression())
                        .findFirst()
                        .orElseThrow(() -> new TlsException("Server selected an unknown compression"));
            }

            case ServerCertificateMessage certificateMessage -> {
                var certificates = certificateMessage.certificates();
                tlsConfig.certificatesHandler()
                        .accept(transmissionLayer.address().orElse(null), certificates, TlsSource.REMOTE);
            }

            case ServerCertificateRequestMessage certificateRequestMessage -> {
                // TODO: Handle request
            }

            case ServerKeyExchangeMessage serverKeyExchangeMessage -> {
                this.serverKeyExchange = serverKeyExchangeMessage.keyExchange();
                // this.negotiatedSignatureAndHashAlgorithm = serverKeyExchangeMessage.signatureAlgorithm();
                this.remoteKeySignature = serverKeyExchangeMessage.signature();
            }

            case ServerFinishedMessage serverFinishedMessage -> {
                // TODO: Validate
            }

            case ClientKeyExchangeMessage _ -> {
                if (serverKeyExchange == null) {
                    throw new TlsException("Missing remote key parameters");
                }

                var preMasterSecret = serverKeyExchange.generatePreMasterSecret(null);
                var masterSecret = TlsMasterSecretKey.of(
                        TlsMode.CLIENT,
                        tlsConfig.version(),
                        negotiatedCipher,
                        preMasterSecret,
                        extendedMasterSecret ? handshakeHash().orElse(null) : null,
                        clientRandomData,
                        serverRandomData
                );
                this.sessionKeys = TlsSessionKeys.of(
                        TlsMode.CLIENT,
                        tlsConfig.version(),
                        negotiatedCipher,
                        masterSecret,
                        clientRandomData,
                        serverRandomData
                );

                this.clientAuth = TlsExchangeAuthenticator.of(
                        tlsConfig.version(),
                        negotiatedCipher.factory().hasAdditionalData() ? TlsHmac.of(negotiatedCipher.hashSupplier().get()) : null,
                        sessionKeys.localMacKey()
                );
                this.clientCipher = negotiatedCipher.factory().newInstance(
                        tlsConfig.version(),
                        clientAuth,
                        sessionKeys.localIv(),
                        sessionKeys.localCipherKey(),
                        true
                );

                this.serverAuth = TlsExchangeAuthenticator.of(
                        tlsConfig.version(),
                        negotiatedCipher.factory().hasAdditionalData() ? TlsHmac.of(negotiatedCipher.hashSupplier().get()) : null,
                        sessionKeys.remoteMacKey()
                );
                this.serverCipher = negotiatedCipher.factory().newInstance(
                        tlsConfig.version(),
                        clientAuth,
                        sessionKeys.remoteIv(),
                        sessionKeys.remoteCipherKey(),
                        false
                );
            }

            case ClientCertificateMessage certificateMessage -> {
                var certificates = certificateMessage.certificates();
                tlsConfig.certificatesHandler()
                        .accept(transmissionLayer.address().orElse(null), certificates, TlsSource.LOCAL);
            }

            case ClientFinishedMessage clientFinishedMessage -> {
                // TODO: Validate
            }

            case ApplicationDataMessage applicationDataMessage -> {
                if (message.source() == TlsSource.REMOTE) {
                    bufferedMessages.add(applicationDataMessage.message());
                }
            }

            case AlertMessage alertMessage -> throw new IllegalArgumentException("Received alert: " + alertMessage);

            default -> {
            }
        }
    }

    private boolean isHandshakeComplete() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_FINISHED);
    }

    private boolean isLocalCipherEnabled() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_FINISHED);
    }

    private boolean isRemoteCipherEnabled() {
        return hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_CHANGE_CIPHER_SPEC) && hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE);
    }

    private boolean hasProcessedHandshakeMessage(TlsMessage.Type type) {
        return processedMessageTypes.contains(type);
    }

    private Optional<byte[]> handshakeHash() {
        if (handshakeHash == null) {
            return Optional.empty();
        } else {
            return Optional.ofNullable(handshakeHash.digest());
        }
    }

    private Optional<byte[]> handshakeVerificationData() {
        if (handshakeHash == null) {
            return Optional.empty();
        } else {
            return Optional.ofNullable(handshakeHash.finish(sessionKeys, TlsMode.CLIENT, TlsSource.LOCAL));
        }
    }

    private void updateHandshakeHash(ByteBuffer buffer, int offset) {
        var length = buffer.remaining() - offset;
        for (var i = 0; i < length; i++) {
            messageDigestBuffer.write(buffer.get(buffer.position() + offset + i));
        }
    }

    private void digestHandshakeHash() {
        if (handshakeHash != null) {
            handshakeHash.update(messageDigestBuffer.toByteArray());
            messageDigestBuffer.reset();
        }
    }

    private OptionalInt explicitNonceLength() {
        return clientCipher != null ? OptionalInt.of(clientCipher.nonceLength()) : OptionalInt.empty();
    }

    private void encrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
        if (clientCipher == null) {
            throw new TlsException("Cannot encrypt a message before enabling the local cipher");
        }

        clientCipher.update(contentType, input, output, null);
    }

    private void decrypt(TlsMessage.ContentType contentType, ByteBuffer input, ByteBuffer output) {
        if (serverCipher == null) {
            throw new TlsException("Cannot decrypt a message before enabling the remote cipher");
        }

        serverCipher.update(contentType, input, output, null);
    }

    private Optional<ByteBuffer> lastBufferedMessage() {
        return bufferedMessages.isEmpty() ? Optional.empty() : Optional.ofNullable(bufferedMessages.poll());
    }

    private void pollBufferedMessage() {
        bufferedMessages.poll();
    }
}
