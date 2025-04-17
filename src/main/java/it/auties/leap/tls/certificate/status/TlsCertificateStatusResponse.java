package it.auties.leap.tls.certificate.status;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

@SuppressWarnings("DuplicatedCode")
public sealed interface TlsCertificateStatusResponse extends TlsSerializableProperty {
    static Ocsp ocsp(byte[] data) {
        if (data == null) {
            throw new TlsAlert("Data cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        return new Ocsp(data);
    }

    static OcspMulti ocspMulti(List<byte[]> data) {
        if (data == null) {
            throw new TlsAlert("Data cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var length = data.stream()
                .mapToInt(entry -> INT16_LENGTH + entry.length)
                .sum();
        return new OcspMulti(data, length);
    }

    TlsCertificateStatusType type();
    TlsCertificateStatusRequest deserialize(ByteBuffer buffer);

    final class Ocsp implements TlsCertificateStatusResponse {
        private final byte[] data;

        Ocsp(byte[] data) {
            this.data = data;
        }

        @Override
        public TlsCertificateStatusType type() {
            return TlsCertificateStatusType.OCSP;
        }

        public byte[] data() {
            return data;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, type().id());
            writeBytesBigEndian24(buffer, data);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + INT24_LENGTH + data.length;
        }

        @Override
        public TlsCertificateStatusRequest deserialize(ByteBuffer buffer) {
            var responderIdLength = readBigEndianInt16(buffer);
            var responderIdList = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, responderIdLength)) {
                var responderId = readBytesBigEndian16(buffer);
                responderIdList.add(responderId);
            }

            var requestExtensionsLength = readBigEndianInt16(buffer);
            var requestExtensions = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, requestExtensionsLength)) {
                var requestExtension = readBytesBigEndian16(buffer);
                requestExtensions.add(requestExtension);
            }

            return new TlsCertificateStatusRequest.Ocsp(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
        }
    }

    final class OcspMulti implements TlsCertificateStatusResponse {
        private final List<byte[]> data;
        private final int length;

        OcspMulti(List<byte[]> data, int length) {
            this.data = data;
            this.length = length;
        }

        @Override
        public TlsCertificateStatusType type() {
            return TlsCertificateStatusType.OCSP_MULTI;
        }

        public List<byte[]> data() {
            return data;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, type().id());
            writeBigEndianInt24(buffer, length);
            for(var data : data) {
                writeBytesBigEndian24(buffer, data);
            }
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + length;
        }

        @Override
        public TlsCertificateStatusRequest deserialize(ByteBuffer buffer) {
            var responderIdLength = readBigEndianInt16(buffer);
            var responderIdList = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, responderIdLength)) {
                var responderId = readBytesBigEndian16(buffer);
                responderIdList.add(responderId);
            }

            var requestExtensionsLength = readBigEndianInt16(buffer);
            var requestExtensions = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, requestExtensionsLength)) {
                var requestExtension = readBytesBigEndian16(buffer);
                requestExtensions.add(requestExtension);
            }

            return new TlsCertificateStatusRequest.OcspMulti(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
        }
    }
}
