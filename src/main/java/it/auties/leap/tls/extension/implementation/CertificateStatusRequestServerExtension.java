package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.certificate.TlsCertificateStatusRequest;
import it.auties.leap.tls.certificate.TlsCertificateStatusResponse;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record CertificateStatusRequestServerExtension(
        TlsCertificateStatusResponse response
) implements TlsExtension.Configured.Server {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        response.serialize(buffer);
    }

    @Override
    public int payloadLength() {
        return response.length();
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public Optional<CertificateStatusRequestClientExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var request = TlsCertificateStatusRequest.of(buffer)
                .orElseThrow(() -> new IllegalArgumentException("Invalid request"));
        var extension = new CertificateStatusRequestClientExtension(request);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return STATUS_REQUEST_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return STATUS_REQUEST_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}