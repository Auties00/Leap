package it.auties.leap.tls.context;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionHandler;
import it.auties.leap.tls.connection.TlsConnectionHandshakeHash;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.extension.TlsExtensionOwner;
import it.auties.leap.tls.message.TlsHandshakeMessageDeserializer;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.*;

@SuppressWarnings({"UnusedReturnValue", "unchecked"})
public class TlsContext {
    private final TlsConnection localConnectionState;
    private final TlsCertificateValidator certificateValidator;
    private final Map<Integer, TlsHandshakeMessageDeserializer> handshakeMessageDeserializers;
    private final TlsConnectionHandler connectionHandler;
    private final Map<TlsProperty<?, ?>, PropertyValue<?, ?>> properties;
    private final Queue<ByteBuffer> bufferedMessages;
    private final TlsConnectionHandshakeHash connectionIntegrity;
    private volatile InetSocketAddress address;
    private volatile TlsConnection remoteConnectionState;
    private volatile TlsConnectionSecret masterSecretKey;

    private final Set<Integer> processedHandshakeExtensions;

    TlsContext(
            TlsConnection localConnectionState,
            TlsCertificateValidator certificateValidator,
            TlsConnectionHandler connectionHandler
    ) {
        this.localConnectionState = localConnectionState;
        this.certificateValidator = certificateValidator;
        this.handshakeMessageDeserializers = new HashMap<>();
        this.connectionHandler = connectionHandler;
        this.properties = new HashMap<>();
        for(var deserializer : TlsHandshakeMessageDeserializer.values()) {
            addHandshakeMessageDeserializer(deserializer);
        }
        this.bufferedMessages = new LinkedList<>();
        this.connectionIntegrity = new TlsConnectionHandshakeHash();
        this.processedHandshakeExtensions = new HashSet<>();
    }

    static TlsContext ofClient(
            List<TlsVersion> versions,
            List<? extends TlsExtensionOwner.Client> extensions,
            List<TlsCipherSuite> ciphers,
            List<TlsCompression> compressions,
            TlsConnection localConnectionState,
            TlsCertificateValidator certificateValidator,
            TlsConnectionHandler connectionHandler
    ) {
        return new TlsContext(localConnectionState, certificateValidator, connectionHandler)
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
            TlsCertificateValidator certificateValidator,
            TlsConnectionHandler connectionHandler
    ) {
        return new TlsContext(localConnectionState, certificateValidator, connectionHandler)
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

    public TlsConnection localConnectionState() {
        return localConnectionState;
    }

    public Optional<TlsConnection> remoteConnectionState() {
        return Optional.ofNullable(remoteConnectionState);
    }

    public TlsConnectionHandler connectionHandler() {
        return connectionHandler;
    }

    public Optional<InetSocketAddress> address() {
        return Optional.ofNullable(address);
    }

    public TlsCertificateValidator certificateValidator() {
        return certificateValidator;
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
            throw new TlsAlert("Missing negotiable property", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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

    public Optional<TlsConnectionSecret> masterSecretKey() {
        return Optional.ofNullable(masterSecretKey);
    }

    public TlsContext setMasterSecretKey(TlsConnectionSecret masterSecretKey) {
        this.masterSecretKey = masterSecretKey;
        return this;
    }

    public TlsConnectionHandshakeHash connectionHandshakeHash() {
        return connectionIntegrity;
    }

    public TlsContext addHandshakeMessageDeserializer(TlsHandshakeMessageDeserializer deserializer) {
        handshakeMessageDeserializers.put(deserializer.id(), deserializer);
        return this;
    }

    public boolean removeHandshakeMessageDeserializer(TlsHandshakeMessageDeserializer deserializer) {
        return handshakeMessageDeserializers.remove(deserializer.id()) != null;
    }

    public Optional<? extends TlsHandshakeMessageDeserializer> findHandshakeMessageDeserializer(int id) {
        return Optional.ofNullable(handshakeMessageDeserializers.get(id));
    }

    public boolean hasProcessedExtension(int type) {
        return processedHandshakeExtensions.contains(type);
    }

    public TlsContext addProcessedExtension(int type) {
        processedHandshakeExtensions.add(type);
        return this;
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
