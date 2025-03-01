package it.auties.leap.socket.async.applicationLayer.implementation;

import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.context.TlsConfig;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.message.TlsMessageType;
import it.auties.leap.tls.message.implementation.*;

import java.io.IOException;
import java.nio.ByteBuffer;
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
            this.tlsContext = new TlsContext(transportLayer.address().orElse(null), tlsConfig);
            this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
            return sendClientHello()
                    .thenCompose(_ -> continueHandshake());
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
        var helloMessage = new HelloMessage.Client(
                tlsContext.config().version(),
                TlsSource.LOCAL,
                tlsContext.localRandomData(),
                tlsContext.localSessionId(),
                tlsContext.localCookie().orElse(null),
                tlsConfig.ciphers(),
                tlsConfig.compressions(),
                tlsContext.processedExtensions(),
                tlsContext.processedExtensionsLength()
        );
        var helloBuffer = writeBuffer();
        helloMessage.serializeMessageWithRecord(helloBuffer);
        tlsContext.updateHandshakeHash(helloBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(handshakeBuffer)
                .thenCompose(_ -> handleOrClose(helloMessage));
    }

    private CompletableFuture<Void> sendClientCertificate() {
        if (!tlsContext.hasProcessedHandshakeMessage(TlsMessageType.SERVER_CERTIFICATE_REQUEST)) {
            return CompletableFuture.completedFuture(null);
        }

        System.out.println("Sending client certificate");
        var certificatesProvider = tlsConfig
                .certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var certificatesMessage = new CertificateMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                certificatesProvider.getCertificates(transportLayer.address().orElse(null))
        );
        var certificatesBuffer = writeBuffer();
        certificatesMessage.serializeMessageWithRecord(certificatesBuffer);
        tlsContext.updateHandshakeHash(certificatesBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(certificatesBuffer)
                .thenCompose(_ -> handleOrClose(certificatesMessage));
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        var keyExchangeMessage = new KeyExchangeMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                (TlsClientKeyExchange) tlsContext.localKeyExchange().orElseThrow()
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

        var clientVerifyCertificate = new CertificateVerifyMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL
        );
        var clientVerifyBuffer = writeBuffer();
        clientVerifyCertificate.serializeMessageWithRecord(clientVerifyBuffer);
        tlsContext.updateHandshakeHash(clientVerifyBuffer, TlsMessage.messageRecordHeaderLength());
        tlsContext.digestHandshakeHash();
        return write(clientVerifyBuffer)
                .thenCompose(_ -> handleOrClose(clientVerifyCertificate));
    }

    private CompletableFuture<Void> sendClientChangeCipher() {
        var changeCipherSpec = new ChangeCipherSpecMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL
        );
        var changeCipherSpecBuffer = writeBuffer();
        changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
        return write(changeCipherSpecBuffer)
                .thenCompose(_ -> handleOrClose(changeCipherSpec));
    }

    private CompletableFuture<Void> sendClientFinish() {
        var handshakeHash = tlsContext.getHandshakeVerificationData(TlsSource.LOCAL)
                .orElseThrow(() -> new TlsException("Missing handshake"));
        var finishedMessage = new FinishedMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                handshakeHash
        );

        var leftPadding = tlsContext.localCipher()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                .ivLength()
                .total();
        var reservedSpace = TlsMessage.messageRecordHeaderLength() + leftPadding;
        var messagePayloadBuffer = writeBuffer()
                .position(reservedSpace);
        finishedMessage.serializeMessagePayload(messagePayloadBuffer);
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
        writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.contentType().id());
        writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().major());
        writeBigEndianInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().minor());
        writeBigEndianInt16(encryptedMessagePayloadBuffer, encryptedMessageLength);
        encryptedMessagePayloadBuffer.position(encryptedMessagePosition);

        return write(encryptedMessagePayloadBuffer)
                .thenCompose(_ -> handleOrClose(finishedMessage));
    }

    private CompletableFuture<Void> readUntilServerDone() {
        if (tlsContext.hasProcessedHandshakeMessage(TlsMessageType.SERVER_HELLO_DONE)) {
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
                var message = tlsContext.remoteCipher()
                        .orElseThrow(() -> new TlsException("Cannot decrypt a message before enabling the remote cipher"))
                        .decrypt(tlsContext, metadata, buffer);
                return handleOrClose(message);
            } else {
                if (!tlsContext.isHandshakeComplete()) {
                    tlsContext.updateHandshakeHash(buffer, 0); // The header isn't included at this point
                }
                var message = TlsMessage.of(tlsContext, buffer, metadata);
                return handleOrClose(message);
            }
        });
    }

    private CompletableFuture<Void> handleOrClose(TlsMessage message) {
        try {
            var result = tlsContext.handleMessage(message);
            if (!result) {
                closeSilently();
                return CompletableFuture.completedFuture(null);
            }

            if (!tlsContext.isHandshakeComplete()) {
                tlsContext.digestHandshakeHash();
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
        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        if (!tlsContext.isLocalCipherEnabled()) {
            return transportLayer.write(buffer);
        }

        assertNotEquals(buffer, tlsBuffer);

        var leftPadding = tlsContext.localCipher()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                .ivLength()
                .total();
        var dataMessage = new ApplicationDataMessage(
                tlsConfig.version(),
                TlsSource.LOCAL,
                buffer
        );
        var encrypted = writeBuffer()
                .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
        tlsContext.localCipher()
                .orElseThrow(() -> new TlsException("Cannot encrypt a message before enabling the local cipher"))
                .encrypt(tlsContext, dataMessage, encrypted);
        TlsMessage.putRecord(
                tlsConfig.version(),
                TlsMessageContentType.APPLICATION_DATA,
                encrypted
        );
        return transportLayer.write(encrypted);
    }

    @Override
    public void close(boolean error) throws IOException {
        if (error || tlsContext == null || !tlsContext.isLocalCipherEnabled()) {
            transportLayer.close();
            return;
        }

        try {
            var leftPadding = tlsContext.localCipher()
                    .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                    .ivLength()
                    .total();
            var alertMessage = new AlertMessage(
                    tlsConfig.version(),
                    TlsSource.LOCAL,
                    AlertMessage.AlertLevel.WARNING,
                    AlertMessage.AlertType.CLOSE_NOTIFY
            );
            var encrypted = writeBuffer()
                    .position(TlsMessage.messageRecordHeaderLength() + leftPadding);
            tlsContext.localCipher()
                    .orElseThrow(() -> new TlsException("Cannot encrypt a message before enabling the local cipher"))
                    .encrypt(tlsContext, alertMessage, encrypted);
            TlsMessage.putRecord(
                    tlsConfig.version(),
                    TlsMessageContentType.ALERT,
                    encrypted
            );
            transportLayer.write(encrypted).join();
        }catch(Throwable _) {

        } finally {
            // Close the socket
            transportLayer.close();
        }
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
