package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.certificate.status.TlsCertificateStatusRequest;
import it.auties.leap.tls.certificate.status.TlsCertificateStatusResponse;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public record CertificateStatusRequestClientExtension(
        TlsCertificateStatusRequest request
) implements TlsExtension.Configured.Client {
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
    public Optional<CertificateStatusRequestServerExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var response = TlsCertificateStatusResponse.of(buffer)
                .orElseThrow(() -> new IllegalArgumentException("Invalid response"));
        var extension = new CertificateStatusRequestServerExtension(response);
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