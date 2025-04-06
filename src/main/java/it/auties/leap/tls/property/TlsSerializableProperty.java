package it.auties.leap.tls.property;

import java.nio.ByteBuffer;

public interface TlsSerializableProperty {
    void serialize(ByteBuffer buffer);
    int length();
}
