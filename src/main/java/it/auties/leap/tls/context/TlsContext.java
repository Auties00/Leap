package it.auties.leap.tls.context;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionHandler;
import it.auties.leap.tls.connection.TlsConnectionHandshakeHash;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.extension.TlsExtension;

import java.net.InetSocketAddress;
import java.util.*;

@SuppressWarnings({"UnusedReturnValue", "unchecked"})
public class TlsContext {
    private final TlsConnection localConnectionState;
    private final TlsCertificateValidator certificateValidator;
    private final TlsConnectionHandler connectionHandler;
    private final Map<TlsContextualProperty<?, ?>, PropertyValue<?, ?>> properties;
    private final Queue<byte[]> bufferedMessages;
    private final TlsConnectionHandshakeHash connectionIntegrity;
    private volatile InetSocketAddress address;
    private volatile TlsConnection remoteConnectionState;
    private volatile TlsConnectionSecret masterSecretKey;
    private final List<? extends TlsExtension> extensions;

    TlsContext(
            TlsConnection localConnectionState,
            List<? extends TlsExtension> extensions,
            TlsCertificateValidator certificateValidator,
            TlsConnectionHandler connectionHandler
    ) {
        this.localConnectionState = localConnectionState;
        this.extensions = extensions;
        this.certificateValidator = certificateValidator;
        this.connectionHandler = connectionHandler;
        this.properties = new HashMap<>();
        this.bufferedMessages = new LinkedList<>();
        this.connectionIntegrity = new TlsConnectionHandshakeHash();
    }

    public static TlsClientContextBuilder clientBuilder() {
        return new TlsClientContextBuilder();
    }

    public static TlsServerContextBuilder serverBuilder() {
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

    public <I, O> TlsContext addAdvertisedValue(TlsContextualProperty<I, O> property, I propertyValue) {
        var value = new PropertyValue<I, O>(propertyValue);
        properties.put(property, value);
        return this;
    }

    public <I, O> TlsContext addNegotiatedValue(TlsContextualProperty<I, O> property, O propertyValue) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            throw new TlsAlert("Missing negotiable property", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        value.setNegotiated(propertyValue);
        return this;
    }

    public <I, O> Optional<I> getAdvertisedValue(TlsContextualProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if(value == null) {
            return Optional.empty();
        }

        return Optional.ofNullable(value.advertised());
    }

    public <I, O> Optional<O> getNegotiatedValue(TlsContextualProperty<I, O> property) {
        var value = (PropertyValue<I, O>) properties.get(property);
        if (value == null) {
            return Optional.empty();
        }

        return value.negotiated();
    }

    public TlsContext addBufferedMessage(byte[] buffer) {
        bufferedMessages.add(buffer);
        return this;
    }

    public Optional<byte[]> lastBufferedMessage() {
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

    public List<? extends TlsExtension> extensions() {
        return Collections.unmodifiableList(extensions);
    }

    private static final class PropertyValue<I, O> {
        private final I advertised;
        private O value;
        private PropertyValue(I advertised) {
            this.advertised = advertised;
        }

        private I advertised() {
            return advertised;
        }

        private Optional<O> negotiated() {
            return Optional.ofNullable(value);
        }

        private void setNegotiated(O negotiated) {
            this.value = negotiated;
        }
    }
}
