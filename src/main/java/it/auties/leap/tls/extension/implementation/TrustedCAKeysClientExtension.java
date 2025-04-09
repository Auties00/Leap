package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.certificate.TlsTrustedAuthority;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.INT16_LENGTH;
import static it.auties.leap.tls.util.BufferUtils.writeBigEndianInt16;

public record TrustedCAKeysClientExtension(
        List<TlsTrustedAuthority> trustedAuthorities,
        int trustedAuthoritiesLength
) implements TlsExtension.Configured.Client {
    public TrustedCAKeysClientExtension(List<TlsTrustedAuthority> trustedAuthorities) {
        var trustedAuthoritiesLength = trustedAuthorities.stream()
                .mapToInt(TlsTrustedAuthority::length)
                .sum();
        this(trustedAuthorities, trustedAuthoritiesLength);
    }
    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, trustedAuthoritiesLength);
        for(var trustedAuthority : trustedAuthorities) {
            trustedAuthority.serialize(buffer);
        }
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH + trustedAuthoritiesLength;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {
        context.addNegotiableProperty(TlsProperty.trustedCA(), trustedAuthorities);
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
