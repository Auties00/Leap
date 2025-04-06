package it.auties.leap.socket.async.applicationLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.cipher.mode.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public class AsyncSecureSocketApplicationLayer extends AsyncSocketApplicationLayer {
    private static final int FRAGMENT_LENGTH = 18432;
    private static final AsyncSocketApplicationLayerFactory<TlsContext> FACTORY = AsyncSecureSocketApplicationLayer::new;

    private final TlsContext tlsContext;
    private ByteBuffer tlsBuffer;

    public AsyncSecureSocketApplicationLayer(AsyncSocketTransportLayer transportLayer, TlsContext tlsContext) {
        super(transportLayer);
        this.tlsContext = tlsContext;
    }

    public static AsyncSocketApplicationLayerFactory<TlsContext> factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> handshake() {
        try {
            var address = transportLayer.address()
                    .orElseThrow(() -> new TlsAlert("Cannot start handshake: no address was set during connection"));
            tlsContext.setAddress(address);
            this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
            return sendClientHello()
                    .thenCompose(_ -> readUntilServerHello())
                    .thenCompose(this::continueHandshake);
        } catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private CompletionStage<Void> continueHandshake(TlsVersion version) {
        return switch (version) {
            case TLS11, TLS12 -> readUntilServerDone()
                    .thenCompose(_ -> sendClientCertificate())
                    .thenCompose(_ -> sendClientKeyExchange())
                    .thenCompose(_ -> sendClientCertificateVerify())
                    .thenCompose(_ -> sendClientChangeCipher())
                    .thenCompose(_ -> sendClientFinish())
                    .thenCompose(_ -> readUntilHandshakeCompleted());

            case TLS13 -> readUntilHandshakeCompleted();

            default -> throw new UnsupportedOperationException();
        };
    }

    private CompletableFuture<Void> sendClientHello() {
        var versions1 = tlsContext.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));
        var versionsSet = new HashSet<>(versions1);
        var legacyVersion = versions1.stream()
                .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                .orElseThrow(() -> new TlsAlert("No version was set in the tls config"))
                .toLegacyVersion();
        var availableCiphers = tlsContext.getNegotiableValue(TlsProperty.cipher())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.cipher()))
                .stream()
                .filter(cipher -> cipher.versions().stream().anyMatch(versionsSet::contains))
                .toList();
        var availableCiphersIds = availableCiphers.stream()
                .map(TlsCipherSuite::id)
                .toList();
        var availableCompressions = tlsContext.getNegotiableValue(TlsProperty.compression())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.compression()));
        var availableCompressionsIds = availableCompressions.stream()
                .map(TlsCompression::id)
                .toList();

        var extensions = tlsContext.getNegotiableValue(TlsProperty.clientExtensions())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.clientExtensions()));
        var supportedVersions = tlsContext.getNegotiableValue(TlsProperty.version())
                .map(HashSet::new)
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));

        var dependenciesTree = new LinkedHashMap<Integer, TlsExtensionOwner.Client>();
        for (var extension : extensions) {
            if (supportedVersions.stream().noneMatch(version -> extension.versions().contains(version))) {
                continue;
            }

            var conflict = dependenciesTree.put(extension.type(), extension);
            if (conflict != null) {
                throw new IllegalArgumentException(extensionConflictError(extension, conflict));
            }

            if (!(extension.dependencies() instanceof TlsExtensionDependencies.Some someExtensionDependencies)) {
                continue;
            }

            var cyclicLinks = someExtensionDependencies.includedTypes()
                    .stream()
                    .map(dependenciesTree::get)
                    .filter(linked -> hasDependency(extension, linked))
                    .toList();
            if (cyclicLinks.isEmpty()) {
                continue;
            }

            var message = cyclicLinks.stream()
                    .map(cyclicLink -> extensionCyclicDependencyError(extension, cyclicLink))
                    .collect(Collectors.joining("\n"));
            throw new IllegalArgumentException(message);
        }

        var results = new ArrayList<TlsExtension.Configured.Client>(dependenciesTree.size());
        var length = 0;
        var deferred = new ArrayList<TlsExtensionOwner.Client>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    switch (configurable.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configurable);
                        case TlsExtensionDependencies.None _ -> {
                            var configured = configurable.configureClient(tlsContext, length);
                            if(configured.isPresent()) {
                                results.add(configured.get());
                                configured.get().apply(tlsContext, TlsSource.LOCAL);
                                length += configured.get().length();
                            }
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                var configured = configurable.configureClient(tlsContext, length);
                                if(configured.isPresent()) {
                                    results.add(configured.get());
                                    configured.get().apply(tlsContext, TlsSource.LOCAL);
                                    length += configured.get().length();
                                }
                            }
                        }
                    }
                }

                case TlsExtension.Configured.Client configured -> {
                    switch (configured.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configured);
                        case TlsExtensionDependencies.None _ -> {
                            results.add(configured);
                            configured.apply(tlsContext, TlsSource.LOCAL);
                            length += configured.length();
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                results.add(configured);
                                configured.apply(tlsContext, TlsSource.LOCAL);
                                length += configured.length();
                            }
                        }
                    }
                }
            }
        }

        for(var extension : deferred) {
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    var configured = configurable.configureClient(tlsContext, length);
                    if(configured.isPresent()) {
                        results.add(configured.get());
                        configured.get().apply(tlsContext, TlsSource.LOCAL);
                        length += configured.get().length();
                    }
                }

                case TlsExtension.Configured.Client configured -> {
                    results.add(configured);
                    configured.apply(tlsContext, TlsSource.LOCAL);
                    length += configured.length();
                }
            }
        }

        tlsContext.addNegotiatedProperty(TlsProperty.clientExtensions(), results);

        var helloMessage = new ClientHelloMessage(
                legacyVersion,
                TlsSource.LOCAL,
                tlsContext.localConnectionState().randomData(),
                tlsContext.localConnectionState().sessionId(),
                tlsContext.localConnectionState().dtlsCookie().orElse(null),
                availableCiphersIds,
                availableCompressionsIds,
                results,
                length
        );
        return write(helloMessage)
                .thenAccept(_ -> helloMessage.apply(tlsContext));
    }

    private static String extensionCyclicDependencyError(TlsExtensionOwner.Client extension, TlsExtensionOwner.Client cyclicLink) {
        return "Extension with type %s defined by <%s> depends cyclically on an extension with type %s defined by <%s>".formatted(
                extension.type(),
                extension.getClass().getName(),
                extension.type(),
                cyclicLink.getClass().getName()
        );
    }

    private static String extensionConflictError(TlsExtensionOwner.Client extension, TlsExtensionOwner.Client conflict) {
        return "Extension with type %s defined by <%s> conflicts with an extension processed previously with type %s defined by <%s>".formatted(
                extension.type(),
                extension.getClass().getName(),
                extension.type(),
                conflict.getClass().getName()
        );
    }

    private boolean hasDependency(TlsExtensionOwner.Client extension, TlsExtensionOwner.Client linked) {
        return linked != null
                && linked.dependencies() instanceof TlsExtensionDependencies.Some nestedSome
                && nestedSome.includedTypes().contains(extension.type());
    }

    private CompletableFuture<Void> sendClientCertificate() {
        if (true) {
            return CompletableFuture.completedFuture(null);
        }

        System.out.println("Sending client certificate");
        var certificatesProvider = tlsContext.certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var certificatesMessage = new CertificateMessage(
                version,
                TlsSource.LOCAL,
                certificatesProvider.get(tlsContext)
        );
        return write(certificatesMessage)
                .thenCompose(_ -> handleOrClose(certificatesMessage));
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var parameters = tlsContext.localConnectionState()
                .keyExchange()
                .orElseThrow(TlsAlert::noLocalKeyExchange);
        var keyExchangeMessage = new ClientKeyExchangeMessage(
                version,
                TlsSource.LOCAL,
                parameters
        );
        return write(keyExchangeMessage)
                .thenCompose(_ -> handleOrClose(keyExchangeMessage));
    }

    private CompletableFuture<Void> sendClientCertificateVerify() {
        if (true) { // !tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CERTIFICATE)
            return CompletableFuture.completedFuture(null);
        }

        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var clientVerifyCertificate = new CertificateVerifyMessage(
                version,
                TlsSource.LOCAL
        );
        return write(clientVerifyCertificate)
                .thenCompose(_ -> handleOrClose(clientVerifyCertificate));
    }

    private CompletableFuture<Void> sendClientChangeCipher() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var changeCipherSpec = new ChangeCipherSpecMessage(
                version,
                TlsSource.LOCAL
        );
        return write(changeCipherSpec)
                .thenCompose(_ -> handleOrClose(changeCipherSpec));
    }

    private CompletableFuture<Void> sendClientFinish() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var handshakeHash = tlsContext.connectionIntegrity()
                .finish(tlsContext, TlsSource.LOCAL);
        var finishedMessage = new FinishedMessage(
                version,
                TlsSource.LOCAL,
                handshakeHash
        );
        return write(finishedMessage)
                .thenCompose(_ -> handleOrClose(finishedMessage));
    }

    private CompletableFuture<TlsVersion> readUntilServerHello() {
        return tlsContext.getNegotiatedValue(TlsProperty.version())
                .map(CompletableFuture::completedFuture)
                .orElseGet(() -> readAndHandleMessage()
                        .thenCompose(_ -> readUntilServerHello()));
    }


    private CompletableFuture<Void> readUntilServerDone() {
        return tlsContext.remoteConnectionState()
                .filter(state -> state.handshakeStatus() == TlsHandshakeStatus.HANDSHAKE_STARTED)
                .map(_ -> CompletableFuture.<Void>completedFuture(null))
                .orElseGet(() -> readAndHandleMessage().thenCompose(_ -> readUntilServerDone()));
    }

    private CompletableFuture<Void> readUntilHandshakeCompleted() {
        return tlsContext.remoteConnectionState()
                .filter(state -> state.handshakeStatus() == TlsHandshakeStatus.HANDSHAKE_FINISHED)
                .map(_ -> CompletableFuture.<Void>completedFuture(null))
                .orElseGet(() -> readAndHandleMessage().thenCompose(_ -> readUntilHandshakeCompleted()));
    }

    @Override
    public CompletableFuture<Void> read(ByteBuffer buffer) {
        if(!isConnected()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
        }

        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        if (!isRemoteCipherEnabled()) {
            return transportLayer.read(buffer);
        }

        return read(buffer, true);
    }

    private CompletableFuture<Void> read(ByteBuffer buffer, boolean lastRead) {
        var message = tlsContext.lastBufferedMessage()
                .orElse(null);
        if (message == null) {
            return readAndHandleMessage()
                    .thenCompose(_ -> read(buffer, lastRead));
        }

        while (buffer.hasRemaining() && message.hasRemaining()) {
            buffer.put(message.get());
        }
        if (!message.hasRemaining()) {
            tlsContext.pollBufferedMessage();
        }
        if(lastRead) {
            buffer.flip();
        }
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public CompletableFuture<Void> readFully(ByteBuffer buffer) {
        return read(buffer, false).thenCompose(_ -> {
            if (buffer.hasRemaining()) {
                return readFully(buffer);
            }

            buffer.flip();
            return CompletableFuture.completedFuture(null);
        });
    }

    private CompletableFuture<Void> readAndHandleMessage() {
        var buffer = readBuffer(TlsMessageMetadata.structureLength());
        return transportLayer.read(buffer)
                .thenApply(_ -> TlsMessageMetadata.of(buffer, TlsSource.REMOTE))
                .thenCompose(this::decodeMessage);
    }

    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata metadata) {
        var buffer = readBuffer(metadata.length());
        return transportLayer.readFully(buffer)
                .thenCompose(_ -> decodeMessage(metadata, buffer));
    }

    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata metadata, ByteBuffer buffer) {
        var position = buffer.position();
        var plaintext = tlsContext.remoteConnectionState()
                .flatMap(TlsConnection::cipher)
                .filter(TlsCipher::enabled)
                .map(cipher -> cipher.decrypt(tlsContext, metadata, buffer))
                .orElse(buffer);
        var message = TlsMessage.of(tlsContext, plaintext, metadata.withLength(plaintext.remaining()))
                .orElseThrow(() -> new TlsAlert("Cannot deserialize message: unknown type"));
        System.err.println("Read " + message.getClass().getName());
        var result = handleOrClose(message);
        if(message instanceof TlsHandshakeMessage) {
            updateHandshakeHash(plaintext.position(position));
        }
        return result;
    }

    private CompletableFuture<Void> handleOrClose(TlsMessage message) {
        try {
            message.apply(tlsContext);
            return CompletableFuture.completedFuture(null);
        }catch (Throwable throwable) {
            try {
                close(true);
            }catch (Throwable closeException) {
                throwable.addSuppressed(closeException);
            }
            return CompletableFuture.failedFuture(throwable);
        }
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        if(!isConnected()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
        }

        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        if (isLocalCipherEnabled()) {
            assertNotEquals(buffer, tlsBuffer);
            var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
            var dataMessage = new ApplicationDataMessage(version, TlsSource.LOCAL, buffer);
            return write(dataMessage);
        }

        return transportLayer.write(buffer);
    }

    private CompletableFuture<Void> write(TlsMessage message){
        return tlsContext.localConnectionState()
                .cipher()
                .filter(TlsCipher::enabled)
                .map(cipher -> {
                    System.err.println("Sending " + message.getClass().getName());

                    // Calculate space requirements
                    var recordLength = recordLength();

                    // Allocate buffers
                    var plaintext = writeBuffer()
                            .position(recordLength + cipher.ivLength());
                    try(var _ = scopedWrite(plaintext, message.length(), true)) {
                        message.serialize(plaintext);
                    }
                    if(message instanceof TlsHandshakeMessage) {
                        var position = plaintext.position();
                        updateHandshakeHash(plaintext.position(position + recordLength()));
                        plaintext.position(position);
                    }
                    var ciphertext = plaintext.duplicate();
                    // Encrypt message in-place
                    cipher.encrypt(message.contentType().id(), ciphertext, plaintext);

                    // Add record header
                    var messageLength = ciphertext.remaining();
                    var newReadPosition = ciphertext.position() - recordLength;
                    ciphertext.position(newReadPosition);
                    serializeRecord(message, ciphertext, messageLength);
                    ciphertext.position(newReadPosition);

                    // Send the message
                    return transportLayer.write(ciphertext);
                })
                .orElseGet(() -> {
                    var buffer = writeBuffer();
                    var length = message.length();
                    try(var _ = scopedWrite(buffer, recordLength() + length, true)) {
                        serializeRecord(message, buffer, length);
                        message.serialize(buffer);
                    }
                    if(message instanceof TlsHandshakeMessage) {
                        var position = buffer.position();
                        updateHandshakeHash(buffer.position(position + recordLength()));
                        buffer.position(position);
                    }

                    return transportLayer.write(buffer);
                });
    }

    // TODO: This needs fragmentation
    // -----------------------------
    private void serializeRecord(TlsMessage message, ByteBuffer buffer, int length) {
        writeBigEndianInt8(buffer, message.contentType().id());
        message.version().serialize(buffer);
        writeBigEndianInt16(buffer, length);
    }

    private int recordLength() {
        return INT8_LENGTH      // contentType
                + INT16_LENGTH  // version
                + INT16_LENGTH; // payloadLength
    }
    // -----------------------------

    @Override
    public void close(boolean error) throws IOException {
        if (error || tlsContext == null || !isLocalCipherEnabled()) {
            transportLayer.close();
            return;
        }

        try {
            var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                    .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
            var alertMessage = new AlertMessage(
                    version,
                    TlsSource.LOCAL,
                    TlsAlertLevel.WARNING,
                    TlsAlertType.CLOSE_NOTIFY
            );
            write(alertMessage);
        }catch(Throwable _) {

        } finally {
            // Close the socket
            transportLayer.close();
        }
    }

    private boolean isLocalCipherEnabled() {
        return tlsContext.localConnectionState()
                .cipher()
                .filter(TlsCipher::enabled)
                .isPresent();
    }

    private boolean isRemoteCipherEnabled() {
        return tlsContext.remoteConnectionState()
                .flatMap(TlsConnection::cipher)
                .filter(TlsCipher::enabled)
                .isPresent();
    }

    public void updateHandshakeHash(ByteBuffer buffer) {
        tlsContext.connectionIntegrity()
                .update(buffer);
        try {
            System.out.println("CURRENT: " + Arrays.toString(tlsContext.connectionIntegrity().finish(tlsContext, TlsSource.REMOTE)));
        }catch (Throwable _) {

        }
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
