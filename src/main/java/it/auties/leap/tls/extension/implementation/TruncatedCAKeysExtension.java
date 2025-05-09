package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateTrustedAuthorities;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.extension.TlsExtension.*;

public sealed class TruncatedCAKeysExtension {
    public static TlsExtension.Client of(TlsCertificateTrustedAuthorities authorities) {
        return new Client(authorities);
    }

    public static TlsExtension.Server of() {
        return new Server();
    }

    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        source.position(source.limit());
        return Optional.of(Server.instance());
    }

    public Optional<? extends TlsExtension.Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        var authorities = TlsCertificateTrustedAuthorities.of(context, source);
        var extension = new Client(authorities);
        return Optional.of(extension);
    }

    public int type() {
        return TRUSTED_CA_KEYS_TYPE;
    }

    public List<TlsVersion> versions() {
        return TRUSTED_CA_KEYS_VERSIONS;
    }

    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    private static final class Client extends TruncatedCAKeysExtension implements TlsExtension.Client, TlsExtensionPayload {
        private final TlsCertificateTrustedAuthorities authorities;

        private Client(TlsCertificateTrustedAuthorities authorities) {
            this.authorities = authorities;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            authorities.serialize(buffer);
        }

        @Override
        public int payloadLength() {
            return authorities.length();
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            context.addAdvertisedValue(TlsContextualProperty.trustedCA(), authorities.trustedAuthoritiesList());
        }


        @Override
        public boolean equals(Object o) {
            return o instanceof TruncatedCAKeysExtension.Client that
                    && Objects.equals(authorities, that.authorities);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(authorities);
        }

        @Override
        public String toString() {
            return "TrustedCAKeysExtension[" +
                    "authorities=" + authorities + ']';
        }

    }

    private static final class Server extends TruncatedCAKeysExtension implements TlsExtension.Server, TlsExtensionPayload {
        private static final TruncatedCAKeysExtension.Server INSTANCE = new TruncatedCAKeysExtension.Server();

        private Server() {

        }

        public static TruncatedCAKeysExtension.Server instance() {
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
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            var trustedCAs = context.getAdvertisedValue(TlsContextualProperty.trustedCA())
                    .orElseThrow(() -> new TlsAlert("Missing negotiable property: trustedCA", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
            context.addNegotiatedValue(TlsContextualProperty.trustedCA(), trustedCAs);
        }

        @Override
        public int hashCode() {
            return type();
        }

        @Override
        public String toString() {
            return "TrustedCAKeysExtension[]";
        }
    }
}
