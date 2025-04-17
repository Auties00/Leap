package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.compressor.TlsCompressor;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

public final class TlsCertificateCompressionAlgorithm implements TlsIdentifiableProperty<Integer> {
    public static TlsCertificateCompressionAlgorithm ZLIB = new TlsCertificateCompressionAlgorithm(1, TlsCompressor.zlib());
    public static TlsCertificateCompressionAlgorithm BROTLI = new TlsCertificateCompressionAlgorithm(2, TlsCompressor.brotli());
    public static TlsCertificateCompressionAlgorithm ZSTD = new TlsCertificateCompressionAlgorithm(3, TlsCompressor.zstd());
    public static TlsCertificateCompressionAlgorithm RESERVED_FOR_EXPERIMENTAL_USE(int id, TlsCompressor compressor) {
        if (id < 16384 || id > 65535) {
            throw new TlsAlert("Only values from 16384-65535 (decimal) inclusive are reserved for Experimental Use", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new TlsCertificateCompressionAlgorithm(id, compressor);
    }

    private final int id;
    private final TlsCompressor compressor;

    private TlsCertificateCompressionAlgorithm(int id, TlsCompressor compressor) {
        this.id = id;
        this.compressor = compressor;
    }

    @Override
    public Integer id() {
        return id;
    }

    public TlsCompressor compressor() {
        return compressor;
    }
}
