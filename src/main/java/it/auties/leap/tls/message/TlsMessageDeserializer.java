package it.auties.leap.tls.message;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.*;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

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
                return Optional.ofNullable(switch (metadata.contentType()) {
                    case HANDSHAKE -> {
                        var id = readBigEndianInt8(buffer);
                        var messageLength = readBigEndianInt24(buffer);
                        try (var _ = scopedRead(buffer, messageLength)) {
                            yield switch (id) {
                                case HelloRequestMessage.ID ->
                                        HelloRequestMessage.of(buffer, metadata);
                                case ServerHelloMessage.ID ->
                                        ServerHelloMessage.of(context, buffer, metadata);
                                case CertificateMessage.ID ->
                                        CertificateMessage.of(buffer, metadata);
                                case ServerKeyExchangeMessage.ID ->
                                        ServerKeyExchangeMessage.of(context, buffer, metadata);
                                case ServerHelloDoneMessage.ID ->
                                        ServerHelloDoneMessage.of(buffer, metadata);
                                case CertificateRequestMessage.ID ->
                                        CertificateRequestMessage.of(buffer, metadata);
                                case FinishedMessage.ID ->
                                        FinishedMessage.of(buffer, metadata);
                                case ClientHelloMessage.ID ->
                                        ClientHelloMessage.of(context, buffer, metadata);
                                case ClientKeyExchangeMessage.ID ->
                                        ClientKeyExchangeMessage.of(context, buffer, metadata);
                                default ->
                                        null;
                            };
                        }
                    }
                    case CHANGE_CIPHER_SPEC -> {
                        var id = readBigEndianInt8(buffer);
                        if(id != ChangeCipherSpecMessage.ID) {
                            throw new TlsAlert("Invalid cipher spec");
                        }

                        yield ChangeCipherSpecMessage.of(buffer, metadata);
                    }
                    case ALERT ->
                            AlertMessage.of(buffer, metadata);
                    case APPLICATION_DATA ->
                            ApplicationDataMessage.of(buffer, metadata);
                });
            }
        };
    }

    Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
