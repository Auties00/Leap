package it.auties.leap.tls.certificate;

import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsCertificateStatusResponse extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty permits TlsCertificateStatusResponse.OCSP {
    static OCSP ocsp(byte[] data) {
        if(data == null) {
            throw new NullPointerException("data");
        }

        return new OCSP(data);
    }

    @SuppressWarnings("SwitchStatementWithTooFewBranches")
    static Optional<? extends TlsCertificateStatusResponse> of(ByteBuffer buffer) {
        var requestId = readBigEndianInt8(buffer);
        return switch (requestId) {
            case OCSP.ID -> Optional.of(OCSP.of(buffer));
            default -> Optional.empty();
        };
    }

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    default int length() {
        return INT8_LENGTH;
    }

    final class OCSP implements TlsCertificateStatusResponse {
        private static final int ID = 1;

        private final byte[] data;

        private OCSP(byte[] data) {
            this.data = data;
        }

        public static OCSP of(ByteBuffer buffer) {
            var data = readBytesBigEndian24(buffer);
            return new OCSP(data);
        }

        @Override
        public Byte id() {
            return ID;
        }

        public byte[] data() {
            return data;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBytesBigEndian24(buffer, data);
        }

        @Override
        public int length() {
            return TlsCertificateStatusResponse.super.length()
                    + INT24_LENGTH + data.length;
        }
    }
}
