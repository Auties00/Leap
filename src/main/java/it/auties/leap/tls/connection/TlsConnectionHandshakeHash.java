package it.auties.leap.tls.connection;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.implementation.ConnectionHandshakeHashDelegate;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.hash.TlsHashFactory;
import it.auties.leap.tls.version.TlsVersion;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

public final class TlsConnectionHandshakeHash extends ByteArrayOutputStream {
    private ConnectionHandshakeHashDelegate delegate;

    public TlsConnectionHandshakeHash() {

    }

    public void init(TlsVersion version, TlsHashFactory factory) {
        if(delegate != null) {
            throw new TlsAlert("Already initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        this.delegate = ConnectionHandshakeHashDelegate.of(version, factory);
        delegate.update(buf, 0, buf.length);
    }

    public void update(ByteBuffer input) {
        if(delegate != null) {
            delegate.update(input);
        }else {
            while (input.hasRemaining()) {
                write(input.get());
            }
        }
    }

    public byte[] digest() {
        if(delegate == null) {
            throw new TlsAlert("Not initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return delegate.digest();
    }

    public byte[] finish(TlsContext context, TlsSource source) {
        if(delegate == null) {
            throw new TlsAlert("Not initialized", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return delegate.finish(context, source);
    }
}
