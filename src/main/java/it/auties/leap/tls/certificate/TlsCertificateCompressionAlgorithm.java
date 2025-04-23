package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.compression.TlsCompressor;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Objects;

public final class TlsCertificateCompressionAlgorithm implements TlsIdentifiableProperty<Integer> {
    private static final TlsCertificateCompressionAlgorithm ZLIB = new TlsCertificateCompressionAlgorithm(1, Type.ZLIB, TlsCompressor.zlib());
    private static final TlsCertificateCompressionAlgorithm BROTLI = new TlsCertificateCompressionAlgorithm(2, Type.BROTLI, TlsCompressor.brotli());
    private static final TlsCertificateCompressionAlgorithm ZSTD = new TlsCertificateCompressionAlgorithm(3, Type.ZSTD, TlsCompressor.zstd());

    private final int id;
    private final Type type;
    private final TlsCompressor compressor;

    private TlsCertificateCompressionAlgorithm(int id, Type type, TlsCompressor compressor) {
        this.id = id;
        this.type = type;
        this.compressor = compressor;
    }

    public static TlsCertificateCompressionAlgorithm zlib() {
        return ZLIB;
    }

    public static TlsCertificateCompressionAlgorithm brotli() {
        return BROTLI;
    }

    public static TlsCertificateCompressionAlgorithm zstd() {
        return ZSTD;
    }

    private static TlsCertificateCompressionAlgorithm reservedForExperimentalUse(int id) {
        return reservedForExperimentalUse(id, null);
    }

    private static TlsCertificateCompressionAlgorithm reservedForExperimentalUse(int id, TlsCompressor compressor) {
        if (id < 16384 || id > 65535) {
            throw new TlsAlert("Only values from 16384-65535 (decimal) inclusive are reserved for Experimental Use", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new TlsCertificateCompressionAlgorithm(id, Type.RESERVED_FOR_EXPERIMENTAL_USE, Objects.requireNonNullElse(compressor, TlsCompressor.unsupported()));
    }

    @Override
    public Integer id() {
        return id;
    }

    public Type type() {
        return type;
    }

    public TlsCompressor compressor() {
        return compressor;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof TlsCertificateCompressionAlgorithm that && that.id == id;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "TlsCertificateCompressionAlgorithm[id=" + id + "]";
    }

    public enum Type {
        PRE_AGREED,
        ZLIB,
        BROTLI,
        ZSTD,
        RESERVED_FOR_EXPERIMENTAL_USE
    }
}
