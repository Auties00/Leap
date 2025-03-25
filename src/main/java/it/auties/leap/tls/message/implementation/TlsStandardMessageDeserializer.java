package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.message.TlsMessage;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.message.TlsMessageMetadata;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsStandardMessageDeserializer implements TlsMessageDeserializer {
    private static final TlsMessageDeserializer INSTANCE = new TlsStandardMessageDeserializer();

    public static TlsMessageDeserializer instance() {
        return INSTANCE;
    }

    @Override
    public Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
        try (var _ = scopedRead(buffer, metadata.messageLength())) {
            return switch (metadata.contentType()) {
                case HANDSHAKE -> {
                    var id = readBigEndianInt8(buffer);
                    var messageLength = readBigEndianInt24(buffer);
                    try (var _ = scopedRead(buffer, messageLength)) {
                        yield Optional.ofNullable(switch (context.selectedMode().orElse(null)) {
                            case CLIENT -> switch (id) {
                                case HelloRequestMessage.Server.ID ->
                                        HelloRequestMessage.Server.of(context, buffer, metadata);
                                case HelloMessage.Server.ID ->
                                        HelloMessage.Server.of(context, buffer, metadata);
                                case CertificateMessage.Server.ID ->
                                        CertificateMessage.Server.of(context, buffer, metadata);
                                case KeyExchangeMessage.Server.ID ->
                                        KeyExchangeMessage.Server.of(context, buffer, metadata);
                                case HelloDoneMessage.Server.ID ->
                                        HelloDoneMessage.Server.of(context, buffer, metadata);
                                case CertificateRequestMessage.Server.ID ->
                                        CertificateRequestMessage.Server.of(context, buffer, metadata);
                                case FinishMessage.Server.ID ->
                                        FinishMessage.Server.of(context, buffer, metadata);
                                default -> null;
                            };
                            case SERVER -> switch (id) {
                                case HelloMessage.Client.ID ->
                                        HelloMessage.Client.of(context, buffer, metadata);
                                case CertificateMessage.Client.ID ->
                                        CertificateMessage.Client.of(context, buffer, metadata);
                                case KeyExchangeMessage.Client.ID ->
                                        KeyExchangeMessage.Client.of(context, buffer, metadata);
                                case FinishMessage.Client.ID ->
                                        FinishMessage.Client.of(context, buffer, metadata);
                                default -> null;
                            };
                            case null -> null;
                        });
                    }
                }
                case CHANGE_CIPHER_SPEC ->
                        Optional.of(ChangeCipherSpecMessage.of(context, buffer, metadata));
                case ALERT ->
                        Optional.of(AlertMessage.of(context, buffer, metadata));
                case APPLICATION_DATA ->
                        Optional.of(ApplicationDataMessage.of(context, buffer, metadata));
            };
        }
    }
}
