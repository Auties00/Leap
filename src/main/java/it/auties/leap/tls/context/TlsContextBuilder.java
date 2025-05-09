package it.auties.leap.tls.context;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.tls.certificate.TlsCertificate;
import it.auties.leap.tls.certificate.TlsCertificateValidator;
import it.auties.leap.tls.ciphersuite.TlsCipherSuite;
import it.auties.leap.tls.compression.TlsCompression;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionHandler;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.util.TlsKeyUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("unchecked")
abstract sealed class TlsContextBuilder<S extends TlsContextBuilder<S, E>, E extends TlsExtension> permits TlsClientContextBuilder, TlsServerContextBuilder {
    final TlsConnectionType mode;
    final List<TlsCertificate> certificates;
    List<TlsVersion> versions;
    List<TlsCipherSuite> ciphers;
    List<TlsCompression> compressions;
    TlsConnectionHandler connectionHandler;
    TlsCertificateValidator certificateValidator;
    byte[] randomData;
    byte[] sessionId;
    byte[] dtlsCookie;
    List<? extends E> extensions;

    TlsContextBuilder(TlsConnectionType mode) {
        this.mode = mode;
        this.certificates = new ArrayList<>();
    }

    public S versions(List<TlsVersion> versions) {
        if(versions != null && !versions.isEmpty()) {
            var protocol = versions.getFirst().protocol();
            for (var i = 1; i < versions.size(); i++) {
                if (versions.get(i).protocol() != protocol) {
                    throw new IllegalArgumentException("Protocol mismatch: versions can only contain one type of protocol");
                }
            }
        }
        this.versions = versions;
        return (S) this;
    }

    public S ciphers(List<TlsCipherSuite> ciphers) {
        this.ciphers = ciphers;
        return (S) this;
    }

    public S compressions(List<TlsCompression> compressions) {
        this.compressions = compressions;
        return (S) this;
    }

    public S randomData(byte[] randomData) {
        this.randomData = randomData;
        return (S) this;
    }

    public S sessionId(byte[] sessionId) {
        this.sessionId = sessionId;
        return (S) this;
    }

    public S dtlsCookie(byte[] dtlsCookie) {
        this.dtlsCookie = dtlsCookie;
        return (S) this;
    }

    public S connectionHandler(TlsConnectionHandler connectionHandler) {
        this.connectionHandler = connectionHandler;
        return (S) this;
    }

    public S certificate(TlsCertificate certificate) {
        this.certificates.add(certificate);
        return (S) this;
    }


    public S certificates(List<TlsCertificate> certificates) {
        this.certificates.addAll(certificates);
        return (S) this;
    }

    public S certificateValidator(TlsCertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
        return (S) this;
    }

    public S extensions(List<? extends E> extensions) {
        this.extensions = extensions;
        return (S) this;
    }

    List<TlsVersion> buildVersions() {
        if (this.versions != null && !this.versions.isEmpty()) {
            return this.versions;
        }

        return TlsVersion.recommended(SocketProtocol.TCP);
    }

    TlsConnection buildLocalConnection(TlsConnectionType type, List<TlsVersion> versions) {
        var randomData = Objects.requireNonNullElseGet(this.randomData, TlsKeyUtils::randomData);
        var sessionId = Objects.requireNonNullElseGet(this.sessionId, TlsKeyUtils::randomData);
        var protocol = versions.getFirst().protocol();
        var dtlsCookie = protocol == SocketProtocol.UDP ? Objects.requireNonNullElseGet(this.dtlsCookie, TlsKeyUtils::randomData) : null;
        return TlsConnection.of(type, randomData, sessionId, dtlsCookie, certificates);
    }

    List<? extends E> buildExtensions(List<TlsVersion> versions) {
        return Objects.requireNonNullElseGet(this.extensions, () -> {
            var results = new ArrayList<E>();
            if(versions.contains(TlsVersion.TLS13) || versions.contains(TlsVersion.DTLS13)) {
                results.add((E) TlsExtension.supportedVersions());
                results.add((E) TlsExtension.supportedGroups());
                results.add((E) TlsExtension.keyShare());
            }

            return results;
        });
    }

    public abstract TlsContext build();
}
