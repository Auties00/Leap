package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;

import java.nio.ByteBuffer;

public interface TlsMessage {
    byte id();
    TlsSource source();
    TlsMessageContentType contentType();
    void validate(TlsContext context);
    void apply(TlsContext context);
    void serialize(ByteBuffer buffer);
    int length();
}
