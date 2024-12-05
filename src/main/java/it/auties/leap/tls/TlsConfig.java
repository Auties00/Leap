package it.auties.leap.tls;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public final class TlsConfig {
    private final TlsVersion version;
    private final List<TlsCipher> ciphers;
    private final List<TlsExtension> extensions;
    private final List<TlsCompression> compressions;
    private final TlsCertificatesProvider certificatesProvider;
    private final TlsCertificatesHandler certificatesHandler;
    private final TlsRenegotiateConnectionHandler renegotiateConnectionHandler;

    public TlsConfig(
            TlsVersion version,
            List<TlsCipher> ciphers,
            List<TlsExtension> extensions,
            List<TlsCompression> compressions,
            TlsCertificatesProvider certificatesProvider,
            TlsCertificatesHandler certificatesHandler,
            TlsRenegotiateConnectionHandler renegotiateConnectionHandler
    ) {
        this.version = version;
        this.ciphers = ciphers;
        this.extensions = extensions;
        this.compressions = compressions;
        this.certificatesProvider = certificatesProvider;
        this.certificatesHandler = certificatesHandler;
        this.renegotiateConnectionHandler = renegotiateConnectionHandler;
    }

    public TlsVersion version() {
        return version;
    }

    public List<TlsCipher> ciphers() {
        return Collections.unmodifiableList(ciphers);
    }

    public List<TlsExtension> extensions() {
        return Collections.unmodifiableList(extensions);
    }

    public List<TlsCompression> compressions() {
        return Collections.unmodifiableList(compressions);
    }

    public Optional<TlsCertificatesProvider> certificatesProvider() {
        return Optional.ofNullable(certificatesProvider);
    }

    public TlsCertificatesHandler certificatesHandler() {
        return certificatesHandler;
    }

    public Optional<TlsRenegotiateConnectionHandler> renegotiateConnectionHandler() {
        return Optional.ofNullable(renegotiateConnectionHandler);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private TlsVersion version;
        private List<TlsCipher> ciphers;
        private List<TlsExtension> extensions;
        private List<TlsCompression> compressions;
        private TlsCertificatesProvider certificatesProvider;
        private TlsCertificatesHandler certificatesHandler;
        private TlsRenegotiateConnectionHandler renegotiateConnectionHandler;
        private Builder() {

        }

        public Builder version(TlsVersion version) {
            this.version = version;
            return this;
        }

        public Builder ciphers(List<TlsCipher> ciphers) {
            this.ciphers = ciphers;
            return this;
        }

        public Builder extensions(List<TlsExtension> extensions) {
            this.extensions = extensions;
            return this;
        }

        public Builder compressions(List<TlsCompression> compressions) {
            this.compressions = compressions;
            return this;
        }

        public Builder certificatesProvider(TlsCertificatesProvider certificatesProvider) {
            this.certificatesProvider = certificatesProvider;
            return this;
        }

        public Builder certificatesHandler(TlsCertificatesHandler certificatesHandler) {
            this.certificatesHandler = certificatesHandler;
            return this;
        }

        public Builder renegotiateConnectionHandler(TlsRenegotiateConnectionHandler renegotiateConnectionHandler) {
            this.renegotiateConnectionHandler = renegotiateConnectionHandler;
            return this;
        }

        public TlsConfig build() {
            return new TlsConfig(
                    Objects.requireNonNull(this.version, "Missing tls version"),
                    Objects.requireNonNullElseGet(ciphers, TlsCipher::recommendedCiphers),
                    Objects.requireNonNull(extensions, "Missing tls extensions"),
                    Objects.requireNonNullElseGet(compressions, () -> List.of(TlsCompression.none())),
                    certificatesProvider,
                    Objects.requireNonNullElseGet(certificatesHandler, TlsCertificatesHandler::validate),
                    renegotiateConnectionHandler
            );
        }
    }
}
