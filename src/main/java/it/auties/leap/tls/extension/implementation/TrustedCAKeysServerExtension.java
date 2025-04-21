package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateTrustedAuthorities;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record TrustedCAKeysServerExtension(

) implements TlsExtension.Configured.Server {
    private static final TrustedCAKeysServerExtension INSTANCE = new TrustedCAKeysServerExtension();

    public static TrustedCAKeysServerExtension instance() {
        return INSTANCE;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {

    }

    @Override
    public int payloadLength() {
        return 0;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        var trustedCAs = context.getNegotiableValue(TlsProperty.trustedCA())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: " + TlsProperty.trustedCA().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        context.addNegotiatedProperty(TlsProperty.trustedCA(), trustedCAs);
    }

    @Override
    public Optional<TrustedCAKeysClientExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var authorities = TlsCertificateTrustedAuthorities.of(context, buffer);
        var extension = new TrustedCAKeysClientExtension(authorities);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return TRUSTED_CA_KEYS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TRUSTED_CA_KEYS_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}
