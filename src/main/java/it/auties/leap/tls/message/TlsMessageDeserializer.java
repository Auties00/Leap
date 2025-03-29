package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.*;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.scopedRead;

@FunctionalInterface
public interface TlsMessageDeserializer {
    static TlsMessageDeserializer of(TlsMessageDeserializer... deserializers) {
        return (context, buffer, metadata) -> {
            for (var deserializer : deserializers) {
                var result = deserializer.deserialize(context, buffer, metadata);
                if (result.isPresent()) {
                    return result;
                }
            }
            return Optional.empty();
        };
    }

    static TlsMessageDeserializer builtin() {
        return (context, buffer, metadata) -> {
            try (var _ = scopedRead(buffer, metadata.length())) {
                return switch (metadata.contentType()) {
                    case HANDSHAKE -> {
                        var id = readBigEndianInt8(buffer);
                        var messageLength = readBigEndianInt24(buffer);
                        try (var _ = scopedRead(buffer, messageLength)) {
                            yield Optional.ofNullable(switch (context.selectedMode().orElse(null)) {
                                case CLIENT -> switch (id) {
                                    case HelloRequestMessage.Server.ID ->
                                            HelloRequestMessage.Server.of(context, buffer, metadata);
                                    case ServerHelloMessage.ID ->
                                            ServerHelloMessage.of(context, buffer, metadata);
                                    case CertificateMessage.Server.ID ->
                                            CertificateMessage.Server.of(context, buffer, metadata);
                                    case ServerKeyExchangeMessage.ID ->
                                            ServerKeyExchangeMessage.of(context, buffer, metadata);
                                    case ServerHelloDoneMessage.Server.ID ->
                                            ServerHelloDoneMessage.Server.of(context, buffer, metadata);
                                    case CertificateRequestMessage.Server.ID ->
                                            CertificateRequestMessage.Server.of(context, buffer, metadata);
                                    case FinishedMessage.Server.ID ->
                                            FinishedMessage.Server.of(context, buffer, metadata);
                                    default -> null;
                                };
                                case SERVER -> switch (id) {
                                    case ClientHelloMessage.ID ->
                                            ClientHelloMessage.of(context, buffer, metadata);
                                    case CertificateMessage.Client.ID ->
                                            CertificateMessage.Client.of(context, buffer, metadata);
                                    case ClientKeyExchangeMessage.ID ->
                                            ClientKeyExchangeMessage.of(context, buffer, metadata);
                                    case FinishedMessage.Client.ID ->
                                            FinishedMessage.Client.of(context, buffer, metadata);
                                    default -> null;
                                };
                                case null -> null;
                            });
                        }
                    }
                    case CHANGE_CIPHER_SPEC ->
                            Optional.of(ChangeCipherSpecMessage.of(context, buffer, metadata));
                    case ALERT ->
                            Optional.of(AlertMessage.of(buffer, metadata));
                    case APPLICATION_DATA ->
                            Optional.of(ApplicationDataMessage.of(buffer, metadata));
                };
            }
        };
    }

    Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
