package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.certificate.TlsCertificateStatus;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

public final class CertificateStatusRequestServerExtension implements TlsExtension.Configured.Server {
    private static final CertificateStatusRequestServerExtension INSTANCE = new CertificateStatusRequestServerExtension();

    private CertificateStatusRequestServerExtension() {

    }

    public static CertificateStatusRequestServerExtension instance() {
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
    public Optional<CertificateStatusRequestClientExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var request = TlsCertificateStatus.Request.of(buffer)
                .orElseThrow(() -> new TlsAlert("Invalid certificate status request", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
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

    @Override
    public int hashCode() {
        return type();
    }

    @Override
    public String toString() {
        return "CertificateStatusRequestServerExtension[]";
    }
}