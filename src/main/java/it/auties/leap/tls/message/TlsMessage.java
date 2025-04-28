package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsSerializableProperty;
import it.auties.leap.tls.version.TlsVersion;

// TODO: Would it make sense to specialize the owner of this message like for TlsExtension? (ie client, server, agnostic)
public interface TlsMessage extends TlsSerializableProperty {
    byte id();
    TlsVersion version();
    TlsSource source();
    TlsMessageContentType contentType();
    void apply(TlsContext context);
}
