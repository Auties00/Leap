package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.compressor.TlsCompressor;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;

public sealed interface TlsCertificateCompressionAlgorithm extends TlsIdentifiableProperty<Integer> {
    static TlsCertificateCompressionAlgorithm brotli() {
        return Brotli.INSTANCE;
    }

    static TlsCertificateCompressionAlgorithm zlib() {
        return Zlib.INSTANCE;
    }

    static TlsCertificateCompressionAlgorithm zstd() {
        return Zstd.INSTANCE;
    }

    static TlsCertificateCompressionAlgorithm reservedForExperimentalUse(int id, TlsCompressor compressor) {
        if(id < 16384 || id > 65535) {
            throw new TlsAlert(
                    "Only values from 16384-65535 (decimal) inclusive are reserved for Experimental Use",
                    URI.create("https://www.rfc-editor.org/rfc/rfc8879.html"),
                    "7.3"
            );
        }

        return new Reserved(id, compressor);
    }

    TlsCompressor compressor();

    final class Zlib implements TlsCertificateCompressionAlgorithm {
        private static final Zlib INSTANCE = new Zlib();

        private Zlib() {

        }

        @Override
        public Integer id() {
            return 1;
        }

        @Override
        public TlsCompressor compressor() {
            return TlsCompressor.zlib();
        }
    }

    final class Brotli implements TlsCertificateCompressionAlgorithm {
        private static final Brotli INSTANCE = new Brotli();

        private Brotli() {

        }

        @Override
        public Integer id() {
            return 2;
        }

        @Override
        public TlsCompressor compressor() {
            return TlsCompressor.brotli();
        }
    }

    final class Zstd implements TlsCertificateCompressionAlgorithm {
        private static final Zstd INSTANCE = new Zstd();

        private Zstd() {

        }

        @Override
        public Integer id() {
            return 3;
        }

        @Override
        public TlsCompressor compressor() {
            return TlsCompressor.zstd();
        }
    }

    final class Reserved implements TlsCertificateCompressionAlgorithm {
        private final int id;
        private final TlsCompressor delegate;
        private Reserved(int id, TlsCompressor delegate) {
            this.id = id;
            this.delegate = delegate;
        }

        @Override
        public Integer id() {
            return id;
        }

        @Override
        public TlsCompressor compressor() {
            if(delegate == null) {
                throw TlsAlert.stub();
            }

            return delegate;
        }
    }
}
