package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsEngine;
import it.auties.leap.tls.TlsSource;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.key.TlsCookie;
import it.auties.leap.tls.key.TlsRandomData;
import it.auties.leap.tls.key.TlsSharedSecret;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class HelloMessage extends TlsHandshakeMessage {
    HelloMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Client extends HelloMessage {
        public static final int ID = 0x01;

        private final TlsRandomData randomData;
        private final TlsSharedSecret sessionId;
        private final TlsCookie cookie;
        private final List<Integer> ciphersIds;
        private final List<TlsCipher> ciphers;
        private final List<Byte> compressionsIds;
        private final List<TlsCompression> compressions;
        private final List<TlsExtension.Concrete> extensions;
        private final int extensionsLength;

        private Client(TlsVersion version, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCookie cookie, List<Integer> ciphersIds, List<TlsCipher> ciphers, List<Byte> compressionsIds, List<TlsCompression> compressions, List<TlsExtension.Concrete> extensions, int extensionsLength) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cookie = cookie;
            this.ciphersIds = ciphersIds;
            this.ciphers = ciphers;
            this.compressionsIds = compressionsIds;
            this.compressions = compressions;
            this.extensions = extensions;
            this.extensionsLength = extensionsLength;
        }

        public Client(TlsVersion tlsVersion, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCookie cookie, List<TlsCipher> ciphers, List<TlsCompression> compressions, List<TlsExtension.Concrete> extensions, int extensionsLength) {
            super(tlsVersion, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cookie = cookie;
            this.ciphers = ciphers;
            this.ciphersIds = List.of();
            this.compressions = compressions;
            this.compressionsIds = List.of();
            this.extensions = extensions;
            this.extensionsLength = extensionsLength;
        }

        public static Client of(TlsEngine engine, ByteBuffer buffer, Metadata metadata) {
            var versionId = TlsVersionId.of(readLittleEndianInt16(buffer));
            var tlsVersion = TlsVersion.of(versionId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
            var clientRandom = TlsRandomData.of(buffer);
            var sessionId = TlsSharedSecret.of(buffer);
            var cookie = TlsCookie.of(metadata.version(), buffer)
                    .orElse(null);
            var ciphersLength = readLittleEndianInt16(buffer);
            var ciphers = new ArrayList<Integer>();
            try(var _ = scopedRead(buffer, ciphersLength)) {
                while (buffer.hasRemaining()) {
                    var cipherId = readLittleEndianInt16(buffer);
                    ciphers.add(cipherId);
                }
            }
            var compressions = new ArrayList<Byte>();
            var compressionsLength = readLittleEndianInt16(buffer);
            try(var _ = scopedRead(buffer, compressionsLength)) {
                while (buffer.hasRemaining()) {
                    var compressionId = readLittleEndianInt8(buffer);
                    compressions.add(compressionId);
                }
            }
            var extensions = new ArrayList<TlsExtension.Concrete>();
            var extensionsLength = readLittleEndianInt16(buffer);
            try(var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readLittleEndianInt16(buffer);
                    var extensionLength = readLittleEndianInt16(buffer);
                    if(extensionLength == 0) {
                        continue;
                    }

                    for(var configurable : engine.config().extensions()) {
                        var extension = configurable.decoder()
                                .decode(buffer, extensionType, TlsEngine.Mode.SERVER);
                        if (extension.isPresent()) {
                            extensions.add(extension.get());
                            break;
                        }
                    }
                }
            }
            return new Client(tlsVersion, metadata.source(), clientRandom, sessionId, cookie, ciphers, List.of(), compressions, List.of(), extensions, extensionsLength);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.CLIENT_HELLO;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer payload) {
            var encodedVersion = switch (version) {
                case TLS13 -> TlsVersion.TLS12;
                case DTLS13 -> TlsVersion.DTLS12;
                default -> version;
            };
            writeLittleEndianInt16(payload, encodedVersion.id().value());

            randomData.serialize(payload);

            sessionId.serialize(payload);

            if(cookie != null) {
                cookie.serialize(payload);
            }

            var ciphersLength = ciphersIds.size() * INT16_LENGTH;
            writeLittleEndianInt16(payload, ciphersLength);
            for (var cipher : ciphersIds) {
                writeLittleEndianInt16(payload, cipher);
            }

            writeLittleEndianInt8(payload, compressionsIds.size());
            for(var compression : compressionsIds) {
                writeLittleEndianInt8(payload, compression);
            }

            if(!extensions.isEmpty()) {
                writeLittleEndianInt16(payload, extensionsLength);
                for (var extension : extensions) {
                    extension.serializeExtension(payload);
                }
            }
        }

        @Override
        public int handshakePayloadLength() {
            var messagePayloadNoExtensionsLength = getMessagePayloadLength(cookie, ciphersIds, compressionsIds);
            return messagePayloadNoExtensionsLength
                    + INT16_LENGTH + extensionsLength;
        }

        public static int getMessagePayloadLength(TlsCookie cookie, List<Integer> ciphers, List<Byte> compressions) {
            return INT16_LENGTH
                    + TlsRandomData.length()
                    + INT8_LENGTH + TlsSharedSecret.length()
                    + (cookie != null ? INT8_LENGTH + cookie.length() : 0)
                    + INT16_LENGTH + ciphers.size() * INT16_LENGTH
                    + INT8_LENGTH + compressions.size() * INT8_LENGTH;
        }

        public TlsRandomData randomData() {
            return randomData;
        }

        public TlsSharedSecret sessionId() {
            return sessionId;
        }

        public List<Integer> ciphersIds() {
            return ciphersIds;
        }

        public List<TlsCipher> ciphers() {
            return ciphers;
        }

        public List<Byte> compressionsIds() {
            return compressionsIds;
        }

        public List<TlsCompression> compressions() {
            return compressions;
        }
    }

    public static final class Server extends HelloMessage {
        public static final byte ID = 0x02;

        private final TlsRandomData randomData;
        private final TlsSharedSecret sessionId;
        private final TlsCipher cipher;
        private final Integer cipherId;
        private final TlsCompression compression;
        private final Byte compressionId;
        private final List<TlsExtension> extensions;
        public Server(TlsVersion version, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, TlsCipher cipher, List<TlsExtension> extensions, TlsCompression compression) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cipherId = null;
            this.cipher = cipher;
            this.extensions = extensions;
            this.compressionId = null;
            this.compression = compression;
        }

        private Server(TlsVersion version, TlsSource source, TlsRandomData randomData, TlsSharedSecret sessionId, int cipherId, List<TlsExtension> extensions, byte compressionId) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cipherId = cipherId;
            this.cipher = null;
            this.extensions = extensions;
            this.compressionId = compressionId;
            this.compression = null;
        }

        public TlsRandomData randomData() {
            return randomData;
        }

        public TlsSharedSecret sessionId() {
            return sessionId;
        }

        public Optional<Integer> cipherId() {
            return Optional.ofNullable(cipherId);
        }

        public Optional<TlsCipher> cipher() {
            return Optional.ofNullable(cipher);
        }

        public Optional<Byte> compressionId() {
            return Optional.ofNullable(compressionId);
        }

        public Optional<TlsCompression> compression() {
            return Optional.ofNullable(compression);
        }

        public List<TlsExtension> extensions() {
            return extensions;
        }

        public static Server of(TlsEngine engine, ByteBuffer buffer, Metadata metadata) {
            var tlsVersionId = readLittleEndianInt16(buffer);
            var tlsVersion = TlsVersion.of(tlsVersionId)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

            var serverRandom = TlsRandomData.of(buffer);

            var sessionId = TlsSharedSecret.of(buffer);

            var cipherId = readLittleEndianInt16(buffer);

            var compressionMethodId = readLittleEndianInt8(buffer);

            var extensions = new ArrayList<TlsExtension>();
            if(buffer.remaining() >= INT16_LENGTH) {
                var extensionsLength = readLittleEndianInt16(buffer);
                try (var _ = scopedRead(buffer, extensionsLength)) {
                    while (buffer.hasRemaining()) {
                        var extensionType = readLittleEndianInt16(buffer);
                        var extensionLength = readLittleEndianInt16(buffer);
                        if (extensionLength == 0) {
                            continue;
                        }

                        for(var inputExtension : engine.config().extensions()) {
                            var extension = inputExtension.decoder()
                                    .decode(buffer, extensionType, TlsEngine.Mode.CLIENT);
                            if (extension.isPresent()) {
                                extensions.add(extension.get());
                                break;
                            }
                        }
                    }
                }
            }
            return new Server(tlsVersion, metadata.source(), serverRandom, sessionId, cipherId, extensions, compressionMethodId);
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public Type type() {
            return Type.SERVER_HELLO;
        }

        @Override
        public ContentType contentType() {
            return ContentType.HANDSHAKE;
        }

        @Override
        public void serializeHandshakePayload(ByteBuffer buffer) {

        }

        @Override
        public int handshakePayloadLength() {
            return 0;
        }
    }
}
