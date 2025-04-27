package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.AlertMessage;
import it.auties.leap.tls.message.implementation.ApplicationDataMessage;
import it.auties.leap.tls.message.implementation.ChangeCipherSpecMessage;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public interface TlsMessageDeserializer {
    static TlsMessageDeserializer alert() {
        return AlertMessage.deserializer();
    }

    static TlsMessageDeserializer applicationData() {
        return ApplicationDataMessage.deserializer();
    }

    static TlsMessageDeserializer changeCipherSpec() {
        return ChangeCipherSpecMessage.deserializer();
    }

    static TlsMessageDeserializer handshake() {
        return TlsHandshakeMessageDeserializer.of();
    }

    static List<TlsMessageDeserializer> values() {
        final class Deserializers {
            private static final List<TlsMessageDeserializer> DESERIALIZERS = List.of(
                    AlertMessage.deserializer(),
                    ApplicationDataMessage.deserializer(),
                    ChangeCipherSpecMessage.deserializer()
            );
        }
        return Deserializers.DESERIALIZERS;
    }

    Optional<TlsMessage> deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
