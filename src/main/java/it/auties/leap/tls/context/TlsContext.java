package it.auties.leap.tls.context;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.TlsCertificatesConsumer;
import it.auties.leap.tls.certificate.TlsCertificatesSupplier;
import it.auties.leap.tls.cipher.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionInitializer;
import it.auties.leap.tls.connection.TlsConnectionIntegrity;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.message.TlsMessageDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.secret.TlsMasterSecretGenerator;
import it.auties.leap.tls.secret.TlsSecret;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.*;

@SuppressWarnings({"UnusedReturnValue", "unchecked"})
public class TlsContext {
    private final TlsCertificatesSupplier certificatesProvider;
    private final TlsCertificatesConsumer certificatesHandler;
    private final KeyStore trustedKeyStore;
    private final TlsMessageDeserializer messageDeserializer;
    private final TlsMasterSecretGenerator masterSecretGenerator;
    private final TlsConnectionInitializer connectionInitializer;
    private final TlsConnection localConnectionState;
    private final Map<TlsProperty<?, ?>, PropertyValue<?, ?>> properties;
    private final Queue<ByteBuffer> bufferedMessages;
    private final TlsConnectionIntegrity connectionIntegrity;
    private volatile InetSocketAddress address;
    private final TlsContextMode mode;
    private volatile TlsConnection remoteConnectionState;
    private volatile TlsSecret masterSecretKey;

    TlsContext(
            TlsContextMode mode,
            TlsConnection localConnectionState,
            TlsCertificatesSupplier certificatesProvider,
            TlsCertificatesConsumer certificatesHandler,
            KeyStore trustedKeyStore,
            TlsMessageDeserializer messageDeserializer,
            TlsMasterSecretGenerator masterSecretGenerator,
            TlsConnectionInitializer connectionInitializer
    ) {
        this.mode = mode;
        this.localConnectionState = localConnectionState;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.trustedKeyStore = trustedKeyStore;
        this.messageDeserializer = messageDeserializer;
        this.masterSecretGenerator = masterSecretGenerator;
        this.connectionInitializer = connectionInitializer;
        this.properties = new HashMap<>();
        this.bufferedMessages = new LinkedList<>();
        this.connectionIntegrity = new TlsConnectionIntegrity();
    }

    static TlsContext ofClient(
            List<TlsVersion> versions,
            List<? extends TlsExtensionOwner.Client> extensions,
            List<TlsCipherSuite> ciphers,
            List<TlsCompression> compressions,
            TlsConnection localConnectionState,
            TlsCertificatesSupplier certificatesProvider,
            TlsCertificatesConsumer certificatesHandler,
            KeyStore trustedKeyStore,
            TlsMessageDeserializer messageDeserializer,
            TlsMasterSecretGenerator masterSecretGenerator,
            TlsConnectionInitializer connectionInitializer
    ) {
        return new TlsContext(TlsContextMode.CLIENT, localConnectionState, certificatesProvider, certificatesHandler, trustedKeyStore, messageDeserializer, masterSecretGenerator, connectionInitializer)
                .addNegotiableProperty(TlsProperty.version(), versions)
                .addNegotiableProperty(TlsProperty.clientExtensions(), extensions)
                .addNegotiableProperty(TlsProperty.cipher(), ciphers)
                .addNegotiableProperty(TlsProperty.compression(), compressions);
    }

    static TlsContext ofServer(
            List<TlsVersion> versions,
            List<? extends TlsExtensionOwner.Server> extensions,
            List<TlsCipherSuite> ciphers,
            List<TlsCompression> compressions,
            TlsConnection localConnectionState,
            TlsCertificatesSupplier certificatesProvider,
            TlsCertificatesConsumer certificatesHandler,
            KeyStore trustedKeyStore,
            TlsMessageDeserializer messageDeserializer,
            TlsMasterSecretGenerator masterSecretGenerator,
            TlsConnectionInitializer connectionInitializer
    ) {
        return new TlsContext(TlsContextMode.SERVER, localConnectionState, certificatesProvider, certificatesHandler, trustedKeyStore, messageDeserializer, masterSecretGenerator, connectionInitializer)
                .addNegotiableProperty(TlsProperty.version(), versions)
                .addNegotiableProperty(TlsProperty.serverExtensions(), extensions)
                .addNegotiableProperty(TlsProperty.cipher(), ciphers)
                .addNegotiableProperty(TlsProperty.compression(), compressions);
    }

    public static TlsClientContextBuilder newClientBuilder() {
        return new TlsClientContextBuilder();
    }

    public static TlsServerContextBuilder newServerBuilder() {
        return new TlsServerContextBuilder();
    }

    public KeyStore trustedKeyStore() {
        return trustedKeyStore;
    }

    public TlsContextMode selectedMode() {
        return mode;
    }

    public TlsCertificatesConsumer certificatesHandler() {
        return certificatesHandler;
    }

    public Optional<TlsCertificatesSupplier> certificatesProvider() {
        return Optional.ofNullable(certificatesProvider);
    }

    public TlsConnection localConnectionState() {
        return localConnectionState;
    }

    public Optional<TlsConnection> remoteConnectionState() {
        return Optional.ofNullable(remoteConnectionState);
    }

    public TlsMessageDeserializer messageDeserializer() {
        return messageDeserializer;
    }

    public TlsMasterSecretGenerator masterSecretGenerator() {
        return masterSecretGenerator;
    }

    public TlsConnectionInitializer connectionInitializer() {
        return connectionInitializer;
    }

    public Optional<InetSocketAddress> address() {
        return Optional.ofNullable(address);
    }

    public TlsContext setRemoteConnectionState(TlsConnection remoteConnectionState) {
        this.remoteConnectionState = remoteConnectionState;
        return this;
    }

    public TlsContext setAddress(InetSocketAddress address) {
        this.address = address;
        return this;
    }

    public <I, O> TlsContext addNegotiableProperty(TlsProperty<I, O> property, I propertyValue) {
        var value = new PropertyValue<I, O>(propertyValue);
        properties.put(property, value);
        return this;
    }

    public <I, O> TlsContext addNegotiatedProperty(TlsProperty<I, O> property, O propertyValue) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            throw TlsAlert.noNegotiableProperty(property);
        }

        value.setNegotiated(propertyValue);
        return this;
    }

    public boolean removeProperty(TlsProperty<?, ?> property) {
        return properties.remove(property) != null;
    }

    public <I, O> Optional<I> getNegotiableValue(TlsProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(value.negotiable());
    }

    public <I, O> Optional<O> getNegotiatedValue(TlsProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if (value == null) {
            return Optional.empty();
        }

        return value.negotiated();
    }

    public TlsContext addBufferedMessage(ByteBuffer buffer) {
        bufferedMessages.add(buffer);
        return this;
    }

    public Optional<ByteBuffer> lastBufferedMessage() {
        return Optional.ofNullable(bufferedMessages.peek());
    }

    public void pollBufferedMessage() {
        bufferedMessages.poll();
    }

    public Optional<TlsSecret> masterSecretKey() {
        return Optional.ofNullable(masterSecretKey);
    }

    public TlsContext setMasterSecretKey(TlsSecret masterSecretKey) {
        this.masterSecretKey = masterSecretKey;
        return this;
    }

    public TlsConnectionIntegrity connectionIntegrity() {
        return connectionIntegrity;
    }

    private static final class PropertyValue<I, O> {
        private final I negotiable;
        private O value;
        private PropertyValue(I negotiable) {
            this.negotiable = negotiable;
        }

        private I negotiable() {
            return negotiable;
        }

        private Optional<O> negotiated() {
            return Optional.ofNullable(value);
        }

        private void setNegotiated(O negotiated) {
            this.value = negotiated;
        }
    }
}
