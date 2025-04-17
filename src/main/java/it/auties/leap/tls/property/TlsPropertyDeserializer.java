package it.auties.leap.tls.property;

import java.nio.ByteBuffer;

public interface TlsPropertyDeserializer<T> {
    T deserialize(ByteBuffer buffer);
}
