package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.*;

import java.nio.ByteBuffer;
import java.util.List;

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

    TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}
