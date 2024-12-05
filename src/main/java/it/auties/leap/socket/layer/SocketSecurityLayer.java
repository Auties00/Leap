package it.auties.leap.socket.layer;

import it.auties.leap.http.decoder.HttpDecodable;
import it.auties.leap.tls.TlsConfig;
import it.auties.leap.tls.TlsRecord;
import it.auties.leap.tls.TlsSpecificationException;
import it.auties.leap.tls.key.TlsPreMasterSecretKey;
import it.auties.leap.tls.engine.TlsEngine;
import it.auties.leap.tls.engine.TlsExtensionsProcessor;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.client.*;
import it.auties.leap.tls.message.shared.ApplicationDataMessage;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static it.auties.leap.tls.TlsRecord.*;

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
        private final TlsConfig tlsConfig;
        private CompletableFuture<Void> sslHandshake;
        private TlsEngine tlsEngine;
        private ByteBuffer tlsBuffer;
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
                    this.tlsBuffer = ByteBuffer.allocate(TlsRecord.FRAGMENT_LENGTH);
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
            var parameters = switch (cipher.keyExchange()) {
                case DH -> {
                    var keyPair = tlsEngine.createKeyPair();
                    yield new TlsPreMasterSecretKey.DH(keyPair.rawPublicKey());
                }
                case DHE -> {
                    var keyPair = tlsEngine.createKeyPair();
                    yield new TlsPreMasterSecretKey.DHE(keyPair.rawPublicKey());
                }
                case ECCPWD -> null;
                case ECDH -> {
                    var keyPair = tlsEngine.localKeyPair()
                            .orElseThrow(() -> new TlsSpecificationException("Cannot send key pair as it wasn't generated"));
                    yield new TlsPreMasterSecretKey.ECDH(keyPair.rawPublicKey());
                }
                case ECDHE -> {
                    var keyPair = tlsEngine.createKeyPair();
                    yield new TlsPreMasterSecretKey.ECDHE(keyPair.rawPublicKey());
                }
                case GOSTR341112_256 -> null;
                case KRB5 -> null;
                case NULL -> new TlsPreMasterSecretKey.NULL();
                case PSK -> null;
                case RSA -> {
                    /*
                    var psk = new byte[0];
                    var data = localRandomData.data();
                    var digest = TlsHashFactory.of(negotiatedCipher.hash());
                    digest.update(psk);
                    digest.update(data);
                    this.localPreMasterSecret = digest.digest();
                    return localPreMasterSecret;
                     */
                    yield null;
                }
                case SRP -> null;
            };
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
                    .orElseThrow(() -> new TlsSpecificationException("Missing handshake"));
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
            writeInt8(encryptedMessagePayloadBuffer, finishedMessage.contentType().id());
            writeInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().major());
            writeInt8(encryptedMessagePayloadBuffer, finishedMessage.version().id().minor());
            writeInt16(encryptedMessagePayloadBuffer, encryptedMessageLength);
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
