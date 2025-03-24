package it.auties.leap.socket.async.applicationLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static it.auties.leap.tls.util.BufferUtils.*;

public class AsyncSecureSocketApplicationLayer extends AsyncSocketApplicationLayer {
    private static final int FRAGMENT_LENGTH = 18432;
    private static final AsyncSocketApplicationLayerFactory<TlsConfig> FACTORY = AsyncSecureSocketApplicationLayer::new;

    private final TlsConfig tlsConfig;
    private ByteBuffer tlsBuffer;
    private TlsContext tlsContext;

    public AsyncSecureSocketApplicationLayer(AsyncSocketTransportLayer transportLayer, TlsConfig tlsConfig) {
        super(transportLayer);
        this.tlsConfig = tlsConfig;
    }

    public static AsyncSocketApplicationLayerFactory<TlsConfig> factory() {
        return FACTORY;
    }

    @Override
    public CompletableFuture<Void> handshake() {
        try {
            var address = transportLayer.address()
                    .orElseThrow(() -> new TlsException("Cannot start handshake: no address was set during connection"));
            this.tlsContext = new TlsContext(address, tlsConfig);
            this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
            return sendClientHello()
                    .thenCompose(_ -> readUntilServerHello())
                    .thenCompose(this::continueHandshake);
        } catch (Throwable throwable) {
            return CompletableFuture.failedFuture(throwable);
        }
    }

    private CompletionStage<Void> continueHandshake(TlsVersion version) {
        System.err.println("Using " + version);
        return switch (version) {
            case TLS12, TLS11 -> readUntilServerDone()
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
        var legacyVersion = tlsContext.negotiableVersions()
                .stream()
                .reduce((first, second) -> first.id().value() > second.id().value() ? first : second)
                .orElseThrow(() -> new TlsException("No version was set in the tls config"))
                .toLegacyVersion();
        var versions = new HashSet<>(tlsConfig.versions());
        var availableCiphers = tlsConfig.ciphers()
                .stream()
                .filter(cipher -> cipher.versions().stream().anyMatch(versions::contains))
                .toList();
        var availableCiphersIds = availableCiphers.stream()
                .map(TlsCipher::id)
                .toList();
        var availableCompressions = tlsConfig.compressions();
        var availableCompressionsIds = availableCompressions.stream()
                .map(TlsCompression::id)
                .toList();
        var helloMessage = new HelloMessage.Client(
                legacyVersion,
                TlsSource.LOCAL,
                tlsContext.localRandomData(),
                tlsContext.localSessionId(),
                tlsContext.localCookie().orElse(null),
                availableCiphersIds,
                availableCompressionsIds,
                tlsContext.processedExtensions(),
                tlsContext.processedExtensionsLength()
        );
        var helloBuffer = writeBuffer();
        helloMessage.serializeMessageWithRecord(helloBuffer);
        tlsContext.updateHandshakeHash(helloBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(handshakeBuffer)
                .thenAccept(_ -> helloMessage.validateAndUpdate(tlsContext));
    }

    private CompletableFuture<Void> sendClientCertificate() {
        if (true) {
            return CompletableFuture.completedFuture(null);
        }

        System.out.println("Sending client certificate");
        var certificatesProvider = tlsConfig.certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var version = tlsContext.negotiatedVersion()
                .orElseThrow(() -> new TlsException("No version was negotiated yet"));
        var certificatesMessage = new CertificateMessage.Client(
                version,
                TlsSource.LOCAL,
                certificatesProvider.get(tlsContext)
        );
        var certificatesBuffer = writeBuffer();
        certificatesMessage.serializeMessageWithRecord(certificatesBuffer);
        tlsContext.updateHandshakeHash(certificatesBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(certificatesBuffer)
                .thenCompose(_ -> handleOrClose(certificatesMessage));
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        var version = tlsContext.negotiatedVersion()
                .orElseThrow(() -> new TlsException("No version was negotiated yet"));
        var keyExchangeMessage = new KeyExchangeMessage.Client(
                version,
                TlsSource.LOCAL,
                tlsContext.localKeyExchange().orElseThrow()
        );
        var keyExchangeBuffer = writeBuffer();
        keyExchangeMessage.serializeMessageWithRecord(keyExchangeBuffer);
        tlsContext.updateHandshakeHash(keyExchangeBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(keyExchangeBuffer)
                .thenCompose(_ -> handleOrClose(keyExchangeMessage));
    }

    private CompletableFuture<Void> sendClientCertificateVerify() {
        if (true) { // !tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.CLIENT_CERTIFICATE)
            return CompletableFuture.completedFuture(null);
        }

        var version = tlsContext.negotiatedVersion()
                .orElseThrow(() -> new TlsException("No version was negotiated yet"));
        var clientVerifyCertificate = new CertificateVerifyMessage.Client(
                version,
                TlsSource.LOCAL
        );
        var clientVerifyBuffer = writeBuffer();
        clientVerifyCertificate.serializeMessageWithRecord(clientVerifyBuffer);
        tlsContext.updateHandshakeHash(clientVerifyBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(clientVerifyBuffer)
                .thenCompose(_ -> handleOrClose(clientVerifyCertificate));
    }

    private CompletableFuture<Void> sendClientChangeCipherAndFinish() {
        var version = tlsContext.negotiatedVersion()
                .orElseThrow(() -> new TlsException("No version was negotiated yet"));
        var changeCipherSpec = new ChangeCipherSpecMessage.Client(
                version,
                TlsSource.LOCAL
        );
        var changeCipherSpecBuffer = writeBuffer();
        changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
        return write(changeCipherSpecBuffer).thenCompose(_ -> {
            var handshakeHash = tlsContext.getHandshakeVerificationData(TlsSource.LOCAL)
                    .orElseThrow(() -> new TlsException("Missing handshake"));
            var finishedMessage = new FinishedMessage.Client(
                    version,
                    TlsSource.LOCAL,
                    handshakeHash
            );

            var leftPadding = tlsContext.localCipher()
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
            tlsContext.localCipher()
                    .orElseThrow(() -> new TlsException("Cannot encrypt a message before enabling the local cipher"))
                    .encrypt(tlsContext, finishedMessage, encryptedMessagePayloadBuffer);

            var encryptedMessagePosition = encryptedMessagePayloadBuffer.position() - TlsMessage.messageRecordHeaderLength();
            var encryptedMessageLength = encryptedMessagePayloadBuffer.remaining();
            encryptedMessagePayloadBuffer.position(encryptedMessagePosition);
            writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.contentType().type());
            writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().major());
            writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().minor());
            writeBigEndianInt16(encryptedMessagePayloadBuffer, encryptedMessageLength);
            encryptedMessagePayloadBuffer.position(encryptedMessagePosition);

            return write(encryptedMessagePayloadBuffer)
                    .thenCompose(_ -> handleOrClose(changeCipherSpec, finishedMessage));
        });
    }

    private CompletableFuture<TlsVersion> readUntilServerHello() {
        return tlsContext.negotiatedVersion()
                .map(CompletableFuture::completedFuture)
                .orElseGet(() -> readAndHandleMessage()
                        .thenCompose(_ -> readUntilServerHello()));
    }


    private CompletableFuture<Void> readUntilServerDone() {
        if (tlsContext.isRemoteHelloDone()) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilServerDone());
    }

    private CompletableFuture<Void> readUntilHandshakeCompleted() {
        if (tlsContext.isHandshakeComplete()) {
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

        if (!tlsContext.isRemoteCipherEnabled()) {
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
        return transportLayer.readFully(buffer).thenCompose(_ -> {
            if (tlsContext.isRemoteCipherEnabled()) {
                var plaintext = tlsContext.remoteCipher()
                        .orElseThrow(() -> new TlsException("Cannot decrypt a message before enabling the remote cipher"))
                        .decrypt(tlsContext, metadata, buffer);
                var message = tlsConfig.messageDeserializer()
                        .deserialize(tlsContext, plaintext, metadata.withMessageLength(plaintext.remaining()))
                        .orElseThrow(() -> new TlsException("Cannot deserialize message: unknown type"));
                return handleOrClose(message);
            } else {
                if (!tlsContext.isHandshakeComplete()) {
                    tlsContext.updateHandshakeHash(buffer, 0); // The header isn't included at this point
                }
                var message = tlsConfig.messageDeserializer()
                        .deserialize(tlsContext, buffer, metadata)
                        .orElseThrow(() -> new TlsException("Cannot deserialize message: unknown type"));
                return handleOrClose(message);
            }
        });
    }

    private CompletableFuture<Void> handleOrClose(TlsMessage... messages) {
        try {
            for(var message : messages) {
                System.out.println("Processing: " + message.getClass().getName());
               message.validateAndUpdate(tlsContext);
                if (!tlsContext.isHandshakeComplete()) {
                    tlsContext.digestHandshakeHash();
                }
            }

            return CompletableFuture.completedFuture(null);
        }catch (TlsException throwable) {
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

        if (tlsContext.isLocalCipherEnabled()) {
            assertNotEquals(buffer, tlsBuffer);
            var leftPadding = tlsContext.localCipher()
                    .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                    .ivLength();
            var version = tlsContext.negotiatedVersion()
                    .orElseThrow(() -> new TlsException("No version was negotiated yet"));
            var dataMessage = new ApplicationDataMessage(
                    version,
                    TlsSource.LOCAL,
                    buffer
            );
            var encrypted = writeBuffer()
                    .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
            tlsContext.localCipher()
                    .orElseThrow(() -> new TlsException("Cannot encrypt a message before enabling the local cipher"))
                    .encrypt(tlsContext, dataMessage, encrypted);
            TlsMessage.putRecord(
                    version,
                    TlsMessageContentType.APPLICATION_DATA,
                    encrypted
            );
            return transportLayer.write(encrypted);
        }

        return transportLayer.write(buffer);
    }

    @Override
    public void close(boolean error) throws IOException {
        if (error || tlsContext == null || !tlsContext.isLocalCipherEnabled()) {
            transportLayer.close();
            return;
        }

        try {
            var version = tlsContext.negotiatedVersion()
                    .orElseThrow(() -> new TlsException("No version was negotiated yet"));
            var leftPadding = tlsContext.localCipher()
                    .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                    .ivLength();
            var alertMessage = new AlertMessage(
                    version,
                    TlsSource.LOCAL,
                    TlsAlertLevel.WARNING,
                    TlsAlertType.CLOSE_NOTIFY
            );
            var encrypted = writeBuffer()
                    .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
            tlsContext.localCipher()
                    .orElseThrow(() -> new TlsException("Cannot encrypt a message before enabling the local cipher"))
                    .encrypt(tlsContext, alertMessage, encrypted);
            TlsMessage.putRecord(
                    version,
                    TlsMessageContentType.ALERT,
                    encrypted
            );
            // Do not await, channel could be closed
            transportLayer.write(encrypted);
        }catch(Throwable _) {

        } finally {
            // Close the socket
            transportLayer.close();
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
