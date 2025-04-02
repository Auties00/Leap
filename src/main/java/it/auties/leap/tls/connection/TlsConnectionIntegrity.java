package it.auties.leap.tls.connection;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.connection.implementation.ConnectionIntegrityDelegate;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

public final class TlsConnectionIntegrity {
    private final ByteArrayOutputStream buffer;
    private ConnectionIntegrityDelegate delegate;

    public TlsConnectionIntegrity() {
        this.buffer = new ByteArrayOutputStream();
    }

    public void init(TlsVersion version, TlsHashFactory factory) {
        if(delegate != null) {
            throw new TlsAlert("Already initialized");
        }

        this.delegate = ConnectionIntegrityDelegate.of(version, factory);
        var buffered = buffer.toByteArray();
        buffer.reset();
        delegate.update(buffered, 0, buffered.length);
    }

    public void update(ByteBuffer input) {
        if(delegate != null) {
            delegate.update(input);
        }else {
            while (input.hasRemaining()) {
                buffer.write(input.get());
            }
        }
    }

    public byte[] digest() {
        if(delegate == null) {
            throw new TlsAlert("Not initialized");
        }

        return delegate.digest();
    }

    public byte[] finish(TlsContext context, TlsSource source) {
        if(delegate == null) {
            throw new TlsAlert("Not initialized");
        }

        return delegate.finish(context, source);
    }
}
