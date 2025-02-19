package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsMode;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.exception.TlsException;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.random.TlsRandomCookie;
import it.auties.leap.tls.random.TlsClientRandom;
import it.auties.leap.tls.random.TlsSessionId;
import it.auties.leap.tls.message.TlsHandshakeMessage;
import it.auties.leap.tls.version.TlsVersion;
import it.auties.leap.tls.version.TlsVersionId;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed abstract class HelloMessage extends TlsHandshakeMessage {
    HelloMessage(TlsVersion version, TlsSource source) {
        super(version, source);
    }

    public static final class Client extends HelloMessage {
        public static final int ID = 0x01;

        private final TlsClientRandom randomData;
        private final TlsSessionId sessionId;
        private final TlsRandomCookie cookie;
        private final List<Integer> ciphersIds;
        private final List<TlsCipher> ciphers;
        private final List<Byte> compressionsIds;
        private final List<TlsCompression> compressions;
        private final List<TlsExtension.Concrete> extensions;
        private final int extensionsLength;

        private Client(TlsVersion version, TlsSource source, TlsClientRandom randomData, TlsSessionId sessionId, TlsRandomCookie cookie, List<Integer> ciphersIds, List<TlsCipher> ciphers, List<Byte> compressionsIds, List<TlsCompression> compressions, List<TlsExtension.Concrete> extensions, int extensionsLength) {
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

        public Client(TlsVersion tlsVersion, TlsSource source, TlsClientRandom randomData, TlsSessionId sessionId, TlsRandomCookie cookie, List<TlsCipher> ciphers, List<TlsCompression> compressions, List<TlsExtension.Concrete> extensions, int extensionsLength) {
            super(tlsVersion, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cookie = cookie;
            this.ciphers = ciphers;
            this.ciphersIds = null;
            this.compressions = compressions;
            this.compressionsIds = null;
            this.extensions = extensions;
            this.extensionsLength = extensionsLength;
        }

        public static Client of(TlsContext context, ByteBuffer buffer, Metadata metadata) {
            var versionId = TlsVersionId.of(readBigEndianInt16(buffer));
            var tlsVersion = TlsVersion.of(versionId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + versionId));
            var clientRandom = TlsClientRandom.of(buffer);
            var sessionId = TlsSessionId.of(buffer);
            var cookie = TlsRandomCookie.of(metadata.version(), buffer)
                    .orElse(null);
            var ciphersLength = readBigEndianInt16(buffer);
            var ciphers = new ArrayList<Integer>();
            try(var _ = scopedRead(buffer, ciphersLength)) {
                while (buffer.hasRemaining()) {
                    var cipherId = readBigEndianInt16(buffer);
                    ciphers.add(cipherId);
                }
            }
            var compressions = new ArrayList<Byte>();
            var compressionsLength = readBigEndianInt16(buffer);
            try(var _ = scopedRead(buffer, compressionsLength)) {
                while (buffer.hasRemaining()) {
                    var compressionId = readBigEndianInt8(buffer);
                    compressions.add(compressionId);
                }
            }
            var extensions = new ArrayList<TlsExtension.Concrete>();
            var extensionsLength = readBigEndianInt16(buffer);
            try(var _ = scopedRead(buffer, extensionsLength)) {
                while (buffer.hasRemaining()) {
                    var extensionType = readBigEndianInt16(buffer);
                    var extensionLength = readBigEndianInt16(buffer);
                    if(extensionLength == 0) {
                        continue;
                    }

                    for(var configurable : context.config().extensions()) {
                        var extension = configurable.decoder()
                                .deserialize(buffer, extensionType, TlsMode.SERVER);
                        if (extension.isPresent()) {
                            extensions.add(extension.get());
                            break;
                        }
                    }
                }
            }
            return new Client(tlsVersion, metadata.source(), clientRandom, sessionId, cookie, ciphers, null, compressions, null, extensions, extensionsLength);
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
            writeBigEndianInt16(payload, encodedVersion.id().value());

            randomData.serialize(payload);

            sessionId.serialize(payload);

            if(cookie != null) {
                cookie.serialize(payload);
            }

            var ciphersLength = getCiphersCount() * INT16_LENGTH;
            writeBigEndianInt16(payload, ciphersLength);
            if(ciphersIds != null) {
                for (var cipher : ciphersIds) {
                    writeBigEndianInt16(payload, cipher);
                }
            }else if(ciphers != null) {
                for (var cipher : ciphers) {
                    writeBigEndianInt16(payload, cipher.id());
                }
            }

            var compressionsLength = getCompressionsCount() * INT8_LENGTH;
            writeBigEndianInt8(payload, compressionsLength);
            if(compressionsIds != null) {
                for (var compression : compressionsIds) {
                    writeBigEndianInt8(payload, compression);
                }
            }else if(compressions != null ) {
                for (var compression : compressions) {
                    writeBigEndianInt8(payload, compression.id());
                }
            }

            if(!extensions.isEmpty()) {
                writeBigEndianInt16(payload, extensionsLength);
                for (var extension : extensions) {
                    extension.serializeExtension(payload);
                }
            }
        }

        @Override
        public int handshakePayloadLength() {
            var messagePayloadNoExtensionsLength = getMessagePayloadLength(cookie, getCiphersCount(), getCompressionsCount());
            return messagePayloadNoExtensionsLength
                    + INT16_LENGTH + extensionsLength;
        }

        private int getCiphersCount() {
            if (ciphersIds != null) {
                return ciphersIds.size();
            }else if(ciphers != null){
                return ciphers.size();
            }else {
                return 0;
            }
        }

        private int getCompressionsCount() {
            if (compressionsIds != null) {
                return compressionsIds.size();
            }else if(compressions != null){
                return compressions.size();
            }else {
                return 0;
            }
        }

        public static int getMessagePayloadLength(TlsRandomCookie cookie, int ciphers, int compressions) {
            return INT16_LENGTH
                    + TlsClientRandom.length()
                    + INT8_LENGTH + TlsSessionId.length()
                    + (cookie != null ? INT8_LENGTH + cookie.length() : 0)
                    + INT16_LENGTH + ciphers * INT16_LENGTH
                    + INT8_LENGTH + compressions * INT8_LENGTH;
        }

        public TlsClientRandom randomData() {
            return randomData;
        }

        public TlsSessionId sessionId() {
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

        private final TlsClientRandom randomData;
        private final TlsSessionId sessionId;
        private final TlsCipher cipher;
        private final Integer cipherId;
        private final TlsCompression compression;
        private final Byte compressionId;
        private final List<TlsExtension> extensions;
        public Server(TlsVersion version, TlsSource source, TlsClientRandom randomData, TlsSessionId sessionId, TlsCipher cipher, List<TlsExtension> extensions, TlsCompression compression) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cipherId = null;
            this.cipher = cipher;
            this.extensions = extensions;
            this.compressionId = null;
            this.compression = compression;
        }

        private Server(TlsVersion version, TlsSource source, TlsClientRandom randomData, TlsSessionId sessionId, int cipherId, List<TlsExtension> extensions, byte compressionId) {
            super(version, source);
            this.randomData = randomData;
            this.sessionId = sessionId;
            this.cipherId = cipherId;
            this.cipher = null;
            this.extensions = extensions;
            this.compressionId = compressionId;
            this.compression = null;
        }

        public TlsClientRandom randomData() {
            return randomData;
        }

        public TlsSessionId sessionId() {
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

        public static Server of(TlsContext context, ByteBuffer buffer, Metadata metadata) {
            var tlsVersionId = readBigEndianInt16(buffer);
            var tlsVersion = TlsVersion.of(tlsVersionId)
                    .orElseThrow(() -> new IllegalArgumentException("Cannot decode TLS message, unknown protocol version: " + tlsVersionId));

            var serverRandom = TlsClientRandom.of(buffer);

            var sessionId = TlsSessionId.of(buffer);

            var cipherId = readBigEndianInt16(buffer);

            var compressionMethodId = readBigEndianInt8(buffer);

            var extensionTypeToDecoder = context.config()
                    .extensions()
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsExtension::extensionType, TlsExtension::decoder));
            var extensions = new ArrayList<TlsExtension>();
            if(buffer.remaining() >= INT16_LENGTH) {
                var extensionsLength = readBigEndianInt16(buffer);
                try (var _ = scopedRead(buffer, extensionsLength)) {
                    while (buffer.hasRemaining()) {
                        var extensionType = readBigEndianInt16(buffer);
                        var extensionLength = readBigEndianInt16(buffer);
                        if (extensionLength == 0) {
                            continue;
                        }

                        var extensionDecoder = extensionTypeToDecoder.get(extensionType);
                        if(extensionDecoder == null) {
                            throw new TlsException("Unknown extension");
                        }

                        extensionDecoder.deserialize(buffer, extensionType, TlsMode.CLIENT)
                                .ifPresent(extensions::add);
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
