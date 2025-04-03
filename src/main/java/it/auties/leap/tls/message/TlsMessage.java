package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;

public interface TlsMessage {
    byte id();
    TlsVersion version();
    TlsSource source();
    TlsMessageContentType contentType();
    void serialize(ByteBuffer buffer);
    int length();
    void apply(TlsContext context);
}
