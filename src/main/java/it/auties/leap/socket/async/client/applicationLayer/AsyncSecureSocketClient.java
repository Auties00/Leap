package it.auties.leap.socket.async.client.applicationLayer;

import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.async.client.AsyncSocketClient;
import it.auties.leap.socket.async.client.AsyncSocketClientTunnel;
import it.auties.leap.socket.async.AsyncSocketImplementation;
import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.implementation.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static it.auties.leap.tls.util.BufferUtils.*;

public class AsyncSecureSocketClient implements AsyncSocketClient {
    private static final int FRAGMENT_LENGTH = 18432;

    private final AsyncSocketImplementation implementation;
    private final AsyncSocketClientTunnel tunnel;
    private final TlsEngine.Config tlsConfig;
    private ByteBuffer tlsBuffer;
    private TlsEngine tlsEngine;

    public AsyncSecureSocketClient(AsyncSocketImplementation implementation, AsyncSocketClientTunnel tunnel, TlsEngine.Config tlsConfig) {
        this.implementation = implementation;
        this.tunnel = tunnel;
        this.tlsConfig = tlsConfig;
    }

    @Override
    public AsyncSocketImplementation implementation() {
        return implementation;
    }

    @Override
    public void close() throws IOException {
        implementation.close();
    }

    @Override
    public CompletableFuture<Void> connect(InetSocketAddress address) {
        return tunnelOrConnect(address)
                .thenCompose(_ -> handshake())
                .exceptionallyCompose(this::closeSilently);
    }

    private CompletableFuture<Void> closeSilently(Throwable throwable) {
        try {
            close();
        }catch (Throwable _) {

        }
        return CompletableFuture.failedFuture(throwable);
    }

    private CompletableFuture<Void> tunnelOrConnect(InetSocketAddress address) {
        if (tunnel != null) {
            return tunnel.connect(address);
        }else {
            return implementation.connect(address);
        }
    }

    private CompletableFuture<Void> handshake() {
        try {
            this.tlsEngine = new TlsEngine(implementation.address().orElse(null), tlsConfig);
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
                tlsEngine.config().version(),
                TlsSource.LOCAL,
                tlsEngine.localRandomData(),
                tlsEngine.localSessionId(),
                tlsEngine.localCookie().orElse(null),
                tlsConfig.ciphers(),
                tlsConfig.compressions(),
                tlsEngine.processedExtensions(),
                tlsEngine.processedExtensionsLength()
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
        var certificatesProvider = tlsConfig
                .certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var certificatesMessage = new CertificateMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                certificatesProvider.getCertificates(implementation.address().orElse(null))
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

        var keyExchangeMessage = new KeyExchangeMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                (TlsClientKeyExchange) tlsEngine.localKeyExchange().orElseThrow()
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
        var clientVerifyCertificate = new CertificateVerifyMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL
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
        var changeCipherSpec = new ChangeCipherSpecMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL
        );
        var changeCipherSpecBuffer = writeBuffer();
        changeCipherSpec.serializeMessageWithRecord(changeCipherSpecBuffer);
        return write(changeCipherSpecBuffer)
                .thenRun(() -> tlsEngine.handleMessage(changeCipherSpec));
    }

    private CompletableFuture<Void> sendClientFinish() {
        var handshakeHash = tlsEngine.getHandshakeVerificationData(TlsSource.LOCAL)
                .orElseThrow(() -> new TlsException("Missing handshake"));
        var finishedMessage = new FinishedMessage.Client(
                tlsConfig.version(),
                TlsSource.LOCAL,
                handshakeHash
        );

        var leftPadding = tlsEngine.localCipher()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                .engine()
                .exportedKeyLength()
                .orElse(0);
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
                TlsMessage.ContentType.HANDSHAKE.id(),
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
        if (tlsEngine.hasProcessedHandshakeMessage(TlsMessage.Type.SERVER_HELLO_DONE)) {
            return CompletableFuture.completedFuture(null);
        }

        return readAndHandleMessage()
                .thenCompose(_ -> readUntilServerDone());
    }

    private CompletableFuture<Void> readUntilHandshakeCompleted() {
        if (tlsEngine.isHandshakeComplete()) {
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

        if (!tlsEngine.isRemoteCipherEnabled()) {
            return implementation.read(buffer);
        }

        return read(buffer, true);
    }

    private CompletableFuture<Void> read(ByteBuffer buffer, boolean lastRead) {
        var message = tlsEngine.lastBufferedMessage()
                .orElse(null);
        if (message == null) {
            return readAndHandleMessage()
                    .thenCompose(_ -> read(buffer, lastRead));
        }

        while (buffer.hasRemaining() && message.hasRemaining()) {
            buffer.put(message.get());
        }
        if (!message.hasRemaining()) {
            tlsEngine.pollBufferedMessage();
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

    @Override
    public boolean isConnected() {
        return implementation.isConnected();
    }

    @Override
    public Optional<InetSocketAddress> address() {
        return implementation.address();
    }

    @Override
    public void setAddress(InetSocketAddress address) {
        implementation.setAddress(address);
    }

    @Override
    public <V> V getOption(SocketOption<V> option) {
        return implementation.getOption(option);
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V value) {
        implementation.setOption(option, value);
    }

    private CompletableFuture<Void> readAndHandleMessage() {
        var buffer = readBuffer(TlsMessage.Metadata.length());
        return implementation.read(buffer)
                .thenApply(_ -> TlsMessage.Metadata.of(buffer))
                .thenCompose(this::decodeMessage);
    }

    private CompletableFuture<Void> decodeMessage(TlsMessage.Metadata metadata) {
        var buffer = readBuffer(metadata.messageLength());
        return implementation.readFully(buffer).thenAccept(_ -> {
            if (tlsEngine.isRemoteCipherEnabled()) {
                var plainBuffer = plainBuffer();
                tlsEngine.decrypt(metadata.contentType().id(), buffer, plainBuffer);
                metadata.setMessageLength(plainBuffer.remaining());
                var message = TlsMessage.of(tlsEngine, plainBuffer, metadata);
                tlsEngine.handleMessage(message);
            } else {
                if (!tlsEngine.isHandshakeComplete()) {
                    tlsEngine.updateHandshakeHash(buffer, 0); // The header isn't included at this point
                }
                var message = TlsMessage.of(tlsEngine, buffer, metadata);
                tlsEngine.handleMessage(message);
                if (!tlsEngine.isHandshakeComplete()) {
                    tlsEngine.digestHandshakeHash();
                }
            }
        });
    }

    @Override
    public CompletableFuture<Void> write(ByteBuffer buffer) {
        if (buffer == null || !buffer.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        if (!tlsEngine.isLocalCipherEnabled()) {
            return implementation.write(buffer);
        }

        // Check that we are not using the same buffer as the tlsBuffer
        assertNotEquals(buffer, tlsBuffer);

        // Serialize the message
        var leftPadding = tlsEngine.localCipher()
                .orElseThrow(() -> new InternalError("Missing negotiated cipher"))
                .engine()
                .exportedKeyLength()
                .orElse(0);
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
        tlsEngine.encrypt(
                TlsMessage.ContentType.APPLICATION_DATA.id(),
                plaintext,
                encrypted
        );
        ApplicationDataMessage.serializeInline(
                tlsConfig.version(),
                encrypted
        );

        // Write the message
        return implementation.write(encrypted);
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
