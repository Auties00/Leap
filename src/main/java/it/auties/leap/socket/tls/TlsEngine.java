package it.auties.leap.socket.tls;

import it.auties.leap.socket.tls.message.ClientHelloMessage;

import java.security.SecureRandom;
import java.util.Set;

public class TlsEngine {
    private final TlsVersion version;
    private final Set<TlsCipher> ciphers;
    private final Set<TlsExtension> extensions;
    private final Set<TlsCompression> compressions;
    private final SecureRandom random;
    public TlsEngine(TlsVersion version, Set<TlsCipher> ciphers, Set<TlsExtension> extensions, Set<TlsCompression> compressions) {
        this.version = version;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
        this.random = new SecureRandom();
    }

    public byte[] beginHandshake() {
        var message = new ClientHelloMessage(version, ciphers, extensions, compressions, random);
        return message.serializeMessage();
    }
}
