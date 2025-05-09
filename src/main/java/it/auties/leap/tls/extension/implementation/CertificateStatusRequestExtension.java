package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static it.auties.leap.tls.extension.TlsExtension.STATUS_REQUEST_TYPE;
import static it.auties.leap.tls.extension.TlsExtension.STATUS_REQUEST_VERSIONS;

public sealed class CertificateStatusRequestExtension {
    public static TlsExtension.Client of(TlsCertificateStatus.Request request) {
        return new Client(request);
    }

    public static TlsExtension.Server of() {
        return Server.instance();
    }

    public int type() {
        return STATUS_REQUEST_TYPE;
    }

    public List<TlsVersion> versions() {
        return STATUS_REQUEST_VERSIONS;
    }

    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }

    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        source.position(source.limit());
        return Optional.of(Server.instance());
    }

    public Optional<? extends TlsExtension.Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        var request = TlsCertificateStatus.Request.of(source)
                .orElseThrow(() -> new TlsAlert("Invalid certificate status request", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        var extension = new Client(request);
        return Optional.of(extension);
    }


    private static final class Client extends CertificateStatusRequestExtension implements TlsExtension.Client, TlsExtensionPayload {
        private final TlsCertificateStatus.Request request;

        private Client(TlsCertificateStatus.Request request) {
            this.request = request;
        }

        @Override
        public void serializePayload(ByteBuffer buffer) {
            request.serialize(buffer);
        }

        @Override
        public int payloadLength() {
            return request.length();
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {

        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof CertificateStatusRequestExtension.Client client
                    && Objects.equals(request, client.request);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(request);
        }

        @Override
        public String toString() {
            return "CertificateStatusRequestServerExtension[" +
                    "request=" + request + ']';
        }
    }

    private static final class Server extends CertificateStatusRequestExtension implements TlsExtension.Server, TlsExtensionPayload {
        private static final CertificateStatusRequestExtension.Server INSTANCE = new CertificateStatusRequestExtension.Server();

        private Server() {

        }

        public static CertificateStatusRequestExtension.Server instance() {
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

        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
        }

        @Override
        public int hashCode() {
            return type();
        }

        @Override
        public String toString() {
            return "CertificateStatusRequestServerExtension[]";
        }
    }
}
