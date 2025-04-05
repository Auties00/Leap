package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;
import static it.auties.leap.tls.util.BufferUtils.scopedRead;

public final class StandardMessageDeserializer implements TlsMessageDeserializer {
    private static final StandardMessageDeserializer INSTANCE = new StandardMessageDeserializer();
    private StandardMessageDeserializer() {

    }

    public static StandardMessageDeserializer instance() {
        return INSTANCE;
    }

    @Override
    public Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
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
                            case ClientCertificateRequestMessage.ID ->
                                    ClientCertificateRequestMessage.of(buffer, metadata);
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
                case CHANGE_CIPHER_SPEC ->
                        ChangeCipherSpecMessage.of(buffer, metadata);
                case ALERT ->
                        AlertMessage.of(buffer, metadata);
                case APPLICATION_DATA ->
                        ApplicationDataMessage.of(buffer, metadata);
            });
        }
    }
}
