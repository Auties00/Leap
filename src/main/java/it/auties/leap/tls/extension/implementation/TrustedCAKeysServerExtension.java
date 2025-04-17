package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.certificate.authority.TlsCertificateTrustedAuthority;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;
import static it.auties.leap.tls.util.BufferUtils.scopedRead;

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
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.trustedCA()));
        context.addNegotiatedProperty(TlsProperty.trustedCA(), trustedCAs);
    }

    @Override
    public Optional<TrustedCAKeysClientExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var trustedAuthoritiesLength = readBigEndianInt16(buffer);
        var trustedAuthorities = new ArrayList<TlsCertificateTrustedAuthority>();
        try(var _ = scopedRead(buffer, trustedAuthoritiesLength)) {
            while (buffer.hasRemaining()) {
                var trustedAuthority = TlsCertificateTrustedAuthority.of(buffer)
                        .orElseThrow(() -> new TlsAlert("Invalid trusted authority"));
                trustedAuthorities.add(trustedAuthority);
            }
        }
        var extension = new TrustedCAKeysClientExtension(trustedAuthorities, trustedAuthoritiesLength);
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
