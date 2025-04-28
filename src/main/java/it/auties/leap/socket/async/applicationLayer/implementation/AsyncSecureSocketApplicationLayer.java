package it.auties.leap.socket.async.applicationLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayer;
import it.auties.leap.socket.async.applicationLayer.AsyncSocketApplicationLayerFactory;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayer;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.ciphersuite.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionHandshakeStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtensionProcessor;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageContentType;
import it.auties.leap.tls.message.TlsMessageMetadata;
import it.auties.leap.tls.message.implementation.*;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.LinkedHashSet;
import java.util.concurrent.CompletableFuture;
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
        var address = transportLayer.address();
        if(address.isEmpty()) {
            return CompletableFuture.failedFuture(new TlsAlert(
                    "Cannot start handshake: no address was set by the tunnel layer",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.HANDSHAKE_FAILURE
            ));
        }

        tlsContext.setAddress(address.get());
        this.tlsBuffer = ByteBuffer.allocate(FRAGMENT_LENGTH);
        return sendClientHello()
                .thenCompose(_ -> readUntil(TlsConnectionHandshakeStatus.HANDSHAKE_STARTED))
                .thenCompose(_ -> continueHandshake());
    }

    private CompletableFuture<Void> continueHandshake() {
        return tlsContext.getNegotiatedValue(TlsProperty.version())
                .map(tlsVersion -> switch (tlsVersion) {
                    case TLS11, TLS12 -> readUntil(TlsConnectionHandshakeStatus.HANDSHAKE_DONE)
                            .thenCompose(_ -> sendClientCertificate())
                            .thenCompose(_ -> sendClientKeyExchange())
                            .thenCompose(_ -> sendClientCertificateVerify())
                            .thenCompose(_ -> sendClientChangeCipher())
                            .thenCompose(_ -> sendClientFinish())
                            .thenCompose(_ -> readUntil(TlsConnectionHandshakeStatus.HANDSHAKE_FINISHED));

                    case TLS13 -> readUntil(TlsConnectionHandshakeStatus.HANDSHAKE_FINISHED)
                            .thenCompose(_ -> sendClientFinish());

                    default -> throw new UnsupportedOperationException();
                })
                .orElseGet(() -> CompletableFuture.failedFuture(new TlsAlert(
                        "Cannot continue handshake: no TLS version was negotiated even though the handshake started",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                )));
    }

    private CompletableFuture<Void> sendClientHello() {
        var versions = tlsContext.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .sorted()
                .collect(Collectors.toCollection(LinkedHashSet::new));
        while (!versions.isEmpty()) {
            var highestVersion = versions.removeLast();
            var legacyVersion = switch (highestVersion) {
                case TLS13 -> TlsVersion.TLS12;
                case DTLS13 -> TlsVersion.DTLS12;
                default -> highestVersion;
            };
            var ciphers = tlsContext.getNegotiableValue(TlsProperty.cipher())
                    .orElseThrow(() -> new TlsAlert("Missing negotiable property: cipher", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(cipher -> cipher.versions().contains(highestVersion))
                    .map(TlsCipherSuite::id)
                    .toList();
            if(ciphers.isEmpty()) {
                continue;
            }

            var compressions = tlsContext.getNegotiableValue(TlsProperty.compression())
                    .orElseThrow(() -> new TlsAlert("Missing negotiable property: compression", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                    .stream()
                    .filter(compression -> compression.versions().contains(highestVersion))
                    .map(TlsCompression::id)
                    .toList();
            if(compressions.isEmpty()) {
                continue;
            }

            var extensions = TlsExtensionProcessor.ofClient(tlsContext);

            var helloMessage = new ClientHelloMessage(
                    legacyVersion,
                    TlsSource.LOCAL,
                    tlsContext.localConnectionState().randomData(),
                    tlsContext.localConnectionState().sessionId(),
                    tlsContext.localConnectionState().dtlsCookie().orElse(null),
                    ciphers,
                    compressions,
                    extensions.values(),
                    extensions.length()
            );
            return write(helloMessage);
        }
        return CompletableFuture.failedFuture(new TlsAlert(
                "Cannot start handshake: no TLS version produces a valid hello message",
                TlsAlertLevel.FATAL,
                TlsAlertType.HANDSHAKE_FAILURE
        ));
    }

    private CompletableFuture<Void> sendClientCertificate() {
        /*
        System.out.println("Sending client certificate");
        var certificatesProvider = tlsContext.certificatesProvider()
                .orElse(null);
        if (certificatesProvider == null) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot provide certificates to the server: no certificates provider was specified in the TLS engine"));
        }

        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var certificatesMessage = new CertificateMessage(
                version,
                TlsSource.LOCAL,
                certificatesProvider.get(tlsContext)
        );
        return write(certificatesMessage);
         */
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> sendClientKeyExchange() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var parameters = tlsContext.localConnectionState()
                .keyExchange()
                .orElseThrow(() -> new TlsAlert("No local key exchange was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var keyExchangeMessage = new ClientKeyExchangeMessage(
                version,
                TlsSource.LOCAL,
                parameters
        );
        return write(keyExchangeMessage);
    }

    private CompletableFuture<Void> sendClientCertificateVerify() {
        /*
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var clientVerifyCertificate = new CertificateVerifyMessage(
                version,
                TlsSource.LOCAL
        );
        return write(clientVerifyCertificate);
         */
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> sendClientChangeCipher() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var changeCipherSpec = new ChangeCipherSpecMessage(
                version,
                TlsSource.LOCAL
        );
        return write(changeCipherSpec);
    }

    private CompletableFuture<Void> sendClientFinish() {
        var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var handshakeHash = tlsContext.connectionHandshakeHash()
                .finish(tlsContext, TlsSource.LOCAL);
        var finishedMessage = new FinishedMessage(
                version,
                TlsSource.LOCAL,
                handshakeHash
        );
        return write(finishedMessage);
    }

    private CompletableFuture<Void> readUntil(TlsConnectionHandshakeStatus status) {
        System.out.println("Reading until " + status);
        return tlsContext.remoteConnectionState()
                .filter(state -> state.handshakeStatus() == status)
                .map(_ -> CompletableFuture.<Void>completedFuture(null))
                .orElseGet(() -> readAndHandleMessage().thenCompose(_ -> readUntil(status)));
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
        return transportLayer.readFully(buffer)
                .thenApply(_ -> TlsMessageMetadata.of(buffer, TlsSource.REMOTE))
                .thenCompose(this::decodeMessage);
    }

    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata metadata) {
        var buffer = readBuffer(metadata.length());
        return transportLayer.readFully(buffer)
                .thenCompose(_ -> decodeMessage(metadata, buffer));
    }

    // TODO: Rewrite this method
    private CompletableFuture<Void> decodeMessage(TlsMessageMetadata ciphertextMetadata, ByteBuffer ciphertext) {
        System.out.println("Handling message: " + ciphertextMetadata);
        var plaintext = tlsContext.remoteConnectionState()
                .flatMap(TlsConnection::cipher)
                .filter(cipher -> cipher.enabled() && (!hasNegotiatedTls13() || ciphertextMetadata.contentType() == TlsMessageContentType.APPLICATION_DATA))
                .map(cipher -> cipher.decrypt(tlsContext, ciphertextMetadata, ciphertext))
                .orElse(ciphertext);
        var plaintextMetadata = ciphertextMetadata.withLength(plaintext.remaining());
        try(var _ = scopedRead(plaintext, plaintextMetadata.length())) {
            var message = plaintextMetadata.contentType()
                    .deserializer()
                    .deserialize(tlsContext, plaintext, plaintextMetadata)
                    .orElseThrow(() -> new TlsAlert("Malformed TLS message: possible plaintext", TlsAlertLevel.FATAL, TlsAlertType.DECODE_ERROR));
            System.out.println("Read message: " + message.getClass().getName());
            return handleOrClose(message);
        }
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
                    .orElseThrow(() -> new TlsAlert("Missing negotiated property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            var dataMessage = new ApplicationDataMessage(version, TlsSource.LOCAL, buffer);
            return write(dataMessage);
        }

        return transportLayer.write(buffer);
    }

    private CompletableFuture<Void> write(TlsMessage message) {
        System.err.println("Sending " + message.getClass().getName());
        var hashable = message instanceof TlsHandshakeMessage handshakeMessage
                && handshakeMessage.hashable();
        var cipher = tlsContext.localConnectionState().cipher();
        if(cipher.isEmpty() || !cipher.get().enabled()) {
            var buffer = writeBuffer();
            var length = message.length();
            try(var _ = scopedWrite(buffer, recordLength() + length, true)) {
                serializeRecord(message, buffer, length);
                message.serialize(buffer);
            }
            if(hashable) {
                var position = buffer.position();
                buffer.position(position + recordLength());
                tlsContext.connectionHandshakeHash().update(buffer);
                buffer.position(position);
            }
            return transportLayer.write(buffer)
                    .thenCompose(_ -> handleOrClose(message))
                    .thenAccept(_ -> {
                        if(hashable) {
                            tlsContext.connectionHandshakeHash().commit();
                        }
                    });
        }

        // Calculate space requirements
        var recordLength = recordLength();
        var negotiatedTls13 = hasNegotiatedTls13();
        var innerContentTypeLength = negotiatedTls13 ? 1 : 0;

        // Allocate buffers
        var plaintext = writeBuffer()
                .position(recordLength + cipher.get().ivLength());
        try(var _ = scopedWrite(plaintext, message.length() + innerContentTypeLength, true)) {
            message.serialize(plaintext);
            if(negotiatedTls13) {
                plaintext.put(message.contentType().id());
            }
        }
        if(hashable) {
            var position = plaintext.position();
            var limit = plaintext.limit();
            plaintext.position(position + recordLength)
                    .limit(limit - innerContentTypeLength);
            tlsContext.connectionHandshakeHash().update(plaintext);
            plaintext.position(position)
                    .limit(limit);
        }
        var ciphertext = plaintext.duplicate()
                .limit(plaintext.capacity());
        // Encrypt message in-place
        cipher.get()
                .encrypt(message.contentType().id(), plaintext, ciphertext);

        // Add record header
        var messageLength = ciphertext.remaining();
        var newReadPosition = ciphertext.position() - recordLength;
        ciphertext.position(newReadPosition);
        serializeRecord(message, ciphertext, messageLength);
        ciphertext.position(newReadPosition);

        // Send the message
        return transportLayer.write(ciphertext)
                .thenCompose(_ -> handleOrClose(message))
                .thenAccept(_ -> {
                    if(hashable) {
                        tlsContext.connectionHandshakeHash().commit();
                    }
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
        if (!error && tlsContext != null && isLocalCipherEnabled()) {
            var version = tlsContext.getNegotiatedValue(TlsProperty.version())
                    .orElse(TlsVersion.TLS10);
            var alertMessage = new AlertMessage(
                    version,
                    TlsSource.LOCAL,
                    TlsAlertLevel.WARNING,
                    TlsAlertType.CLOSE_NOTIFY
            );
            write(alertMessage);
        }

        transportLayer.close();
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

    private boolean hasNegotiatedTls13() {
        return tlsContext.getNegotiatedValue(TlsProperty.version())
                .filter(version -> version == TlsVersion.TLS13 || version == TlsVersion.DTLS13)
                .isPresent();
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
