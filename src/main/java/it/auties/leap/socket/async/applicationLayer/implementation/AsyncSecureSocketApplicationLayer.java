package it.auties.leap.socket.async.applicationLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static it.auties.leap.tls.util.BufferUtils.assertNotEquals;

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
                    .thenCompose(_ -> sendClientChangeCipherAndFinish())
                    .thenCompose(_ -> readUntilHandshakeCompleted());

            case TLS13 -> readUntilHandshakeCompleted();

            default -> throw new UnsupportedOperationException();
        };
    }

    private CompletableFuture<Void> sendClientHello() {
        var handshakeBuffer = writeBuffer();
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
                .map(TlsCipher::id)
                .toList();
        var availableCompressions = tlsContext.getNegotiableValue(TlsProperty.compression())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.compression()));
        var availableCompressionsIds = availableCompressions.stream()
                .map(TlsCompression::id)
                .toList();
        var extensions = tlsContext.extensionsInitializer()
                .process(tlsContext);
        var helloMessage = new HelloMessage.Client(
                legacyVersion,
                TlsSource.LOCAL,
                tlsContext.localConnectionState().randomData(),
                tlsContext.localConnectionState().sessionId(),
                tlsContext.localConnectionState().dtlsCookie().orElse(null),
                availableCiphersIds,
                availableCompressionsIds,
                extensions.content(),
                extensions.length()
        );
        var helloBuffer = writeBuffer();
        helloMessage.serializeMessageWithRecord(helloBuffer);
        updateHandshakeHash(helloBuffer, TlsMessage.messageRecordHeaderLength());
        return write(handshakeBuffer)
                .thenAccept(_ -> helloMessage.apply(tlsContext));
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
        var certificatesMessage = new CertificateMessage.Client(
                version,
                TlsSource.LOCAL,
                certificatesProvider.get(tlsContext)
        );
        var certificatesBuffer = writeBuffer();
        certificatesMessage.serializeMessageWithRecord(certificatesBuffer);
        updateHandshakeHash(certificatesBuffer, TlsMessage.messageRecordHeaderLength());
        return write(certificatesBuffer)
                .thenCompose(_ -> handleOrClose(certificatesMessage));
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var parameters = tlsContext.localConnectionState()
                .keyExchange()
                .orElseThrow(TlsAlert::noLocalKeyExchange);
        var keyExchangeMessage = new KeyExchangeMessage.Client(
                version,
                TlsSource.LOCAL,
                parameters
        );
        var keyExchangeBuffer = writeBuffer();
        keyExchangeMessage.serializeMessageWithRecord(keyExchangeBuffer);
        updateHandshakeHash(keyExchangeBuffer, TlsMessage.messageRecordHeaderLength());
        return write(keyExchangeBuffer)
                .thenCompose(_ -> handleOrClose(keyExchangeMessage));
    }

    private CompletableFuture<Void> sendClientCertificateVerify() {
        if (true) { // !tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CERTIFICATE)
            return CompletableFuture.completedFuture(null);
        }

        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var clientVerifyCertificate = new CertificateVerifyMessage.Client(
                version,
                TlsSource.LOCAL
        );
        var clientVerifyBuffer = writeBuffer();
        clientVerifyCertificate.serializeMessageWithRecord(clientVerifyBuffer);
        updateHandshakeHash(clientVerifyBuffer, TlsMessage.messageRecordHeaderLength());
        return write(clientVerifyBuffer)
                .thenCompose(_ -> handleOrClose(clientVerifyCertificate));
    }

    private CompletableFuture<Void> sendClientChangeCipherAndFinish() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> TlsAlert.noNegotiatedProperty(TlsProperty.version()));
        var changeCipherSpec = new ChangeCipherSpecMessage.Client(
                version,
                TlsSource.LOCAL
        );
        var changeCipherSpecBuffer = writeBuffer();
        changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
        return write(changeCipherSpecBuffer).thenCompose(_ -> {
            var handshakeHash = getHandshakeVerificationData(TlsSource.LOCAL);
            var finishedMessage = new FinishedMessage.Client(
                    version,
                    TlsSource.LOCAL,
                    handshakeHash
            );
            return write(finishedMessage)
                    .thenCompose(_ -> handleOrClose(changeCipherSpec, finishedMessage));
        });
    }

    private CompletableFuture<TlsVersion> readUntilServerHello() {
        return tlsContext.getNegotiatedValue(TlsProperty.version())
                .map(CompletableFuture::completedFuture)
                .orElseGet(() -> readAndHandleMessage()
                        .thenCompose(_ -> readUntilServerHello()));
    }


    private CompletableFuture<Void> readUntilServerDone() {
        if (false) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilServerDone());
    }

    private CompletableFuture<Void> readUntilHandshakeCompleted() {
        if (false) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilHandshakeCompleted());
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
        var buffer = readBuffer(TlsMessageMetadata.length());
        return transportLayer.read(buffer)
                .thenApply(_ -> TlsMessageMetadata.of(buffer))
                .thenCompose(this::decodeMessage);
    }

    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata metadata) {
        var buffer = readBuffer(metadata.messageLength());
        return transportLayer.readFully(buffer)
                .thenCompose(_ -> decodeMessage(metadata, buffer));
    }

    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata metadata, ByteBuffer buffer) {
        return tlsContext.remoteConnectionState()
                .flatMap(TlsConnection::cipher)
                .map(cipher -> {
                    var plaintext = cipher.decrypt(tlsContext, metadata, buffer);
                    var message = tlsContext.messageDeserializer()
                            .deserialize(tlsContext, plaintext, metadata.withMessageLength(plaintext.remaining()))
                            .orElseThrow(() -> new TlsAlert("Cannot deserialize message: unknown type"));
                    return handleOrClose(message);
                })
                .orElseGet(() -> {
                    updateHandshakeHash(buffer, 0); // The header isn't included at this point
                    var message = tlsContext.messageDeserializer()
                            .deserialize(tlsContext, buffer, metadata)
                            .orElseThrow(() -> new TlsAlert("Cannot deserialize message: unknown type"));
                    return handleOrClose(message);
                });
    }

    private CompletableFuture<Void> handleOrClose(TlsMessage... messages) {
        try {
            for(var message : messages) {
                System.out.println("Processing: " + message.getClass().getName());
                message.apply(tlsContext);
            }

            return CompletableFuture.completedFuture(null);
        }catch (TlsAlert throwable) {
            closeSilently();
            throw throwable;
        }catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private void closeSilently() {
        try {
            close(true);
        }catch (IOException _) {

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
        var leftPadding = tlsContext.localConnectionState()
                .cipher()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                .ivLength();
        var reservedSpace = TlsMessage.messageRecordHeaderLength() + leftPadding;
        var messagePayloadBuffer = writeBuffer()
                .position(reservedSpace);
        messagePayloadBuffer.limit(messagePayloadBuffer.position())
                .position(reservedSpace);

        var encryptedMessagePayloadBuffer = messagePayloadBuffer.duplicate()
                .limit(messagePayloadBuffer.capacity())
                .position(reservedSpace);
        tlsContext.localConnectionState()
                .cipher()
                .orElseThrow(() -> new TlsAlert("Cannot encrypt a message before enabling the local cipher"))
                .encrypt(tlsContext, message, encryptedMessagePayloadBuffer);

        TlsMessage.putRecord(
                message.version(),
                message.contentType(),
                encryptedMessagePayloadBuffer
        );

        return write(encryptedMessagePayloadBuffer);
    }

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
                .isPresent();
    }

    private boolean isRemoteCipherEnabled() {
        return tlsContext.remoteConnectionState()
                .flatMap(TlsConnection::cipher)
                .isPresent();
    }

    public byte[] getHandshakeVerificationData(TlsSource source) {
        return tlsContext.connectionIntegrity()
                .finish(tlsContext, source);
    }

    public void updateHandshakeHash(ByteBuffer buffer, int offset) {
        var position = buffer.position();
        tlsContext.connectionIntegrity()
                .update(buffer.position(position + offset));
        buffer.position(position);
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
