package it.auties.leap.tls.extension.implementation;

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

public record TrustedCAKeysClientExtension(
        TlsCertificateTrustedAuthorities authorities
) implements TlsExtension.Configured.Client {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        authorities.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return authorities.length();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        context.addNegotiableProperty(TlsProperty.trustedCA(), authorities.trustedAuthoritiesList());
    }

    @Override
    public Optional<TrustedCAKeysServerExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        buffer.position(buffer.limit());
        return Optional.of(TrustedCAKeysServerExtension.instance());
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
