package it.auties.leap.tls.context;

import it.auties.leap.tls.cipher.TlsCipher;
import it.auties.leap.tls.compression.TlsCompression;

import java.util.Collection;

sealed public interface TlsContextUpdate {
    record Mode(TlsMode oldMode, TlsMode newMode) implements TlsContextUpdate {

    }

    record Ciphers(Collection<TlsCipher> oldCiphers, Collection<TlsCipher> newCiphers) implements TlsContextUpdate {

    }

    record Compressions(Collection<TlsCompression> oldCompressions,
                        Collection<TlsCompression> newCompressions) implements TlsContextUpdate {

    }

    record HandshakeMessage(int type, TlsSource tlsSource) implements TlsContextUpdate {

    }
}
