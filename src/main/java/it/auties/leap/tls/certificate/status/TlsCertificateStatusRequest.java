package it.auties.leap.tls.certificate.status;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

// https://www.rfc-editor.org/rfc/rfc6066.html
@SuppressWarnings("DuplicatedCode")
public sealed interface TlsCertificateStatusRequest extends TlsSerializableProperty {
    static Ocsp ocsp(List<byte[]> responderId, List<byte[]> requestExtensions) {
        if (responderId == null) {
            throw new TlsAlert("Responder id cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if (requestExtensions == null) {
            throw new TlsAlert("Request extensions cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var responderIdLength = getInt16ByteArrayLength(responderId);
        var requestExtensionsLength = getInt16ByteArrayLength(requestExtensions);

        return new Ocsp(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
    }

    static OcspMulti ocspMulti(List<byte[]> responderId, List<byte[]> requestExtensions) {
        if (responderId == null) {
            throw new TlsAlert("Responder id cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if (requestExtensions == null) {
            throw new TlsAlert("Request extensions cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var responderIdLength = getInt16ByteArrayLength(responderId);
        var requestExtensionsLength = getInt16ByteArrayLength(requestExtensions);

        return new OcspMulti(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
    }

    private static int getInt16ByteArrayLength(List<byte[]> requestExtensions) {
        return requestExtensions
                .stream()
                .mapToInt(bytes -> INT16_LENGTH + bytes.length)
                .sum();
    }

    TlsCertificateStatusType type();
    TlsCertificateStatusResponse deserialize(ByteBuffer buffer);

    final class Ocsp implements TlsCertificateStatusRequest {
        private final List<byte[]> responderIdList;
        private final int responderIdListLength;
        private final List<byte[]> requestExtensions;
        private final int requestExtensionsLength;

        Ocsp(List<byte[]> responderIdList, int responderIdListLength, List<byte[]> requestExtensions, int requestExtensionsLength) {
            this.responderIdList = responderIdList;
            this.responderIdListLength = responderIdListLength;
            this.requestExtensions = requestExtensions;
            this.requestExtensionsLength = requestExtensionsLength;
        }

        @Override
        public TlsCertificateStatusType type() {
            return TlsCertificateStatusType.OCSP;
        }

        public List<byte[]> responderIdList() {
            return Collections.unmodifiableList(responderIdList);
        }

        public List<byte[]> requestExtensions() {
            return Collections.unmodifiableList(requestExtensions);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, type().id());
            if(responderIdListLength > 0) {
                writeBigEndianInt16(buffer, responderIdListLength);
                for(var responderId : responderIdList) {
                    writeBytesBigEndian16(buffer, responderId);
                }
            }
            if(requestExtensionsLength > 0) {
                writeBigEndianInt16(buffer, requestExtensionsLength);
                for(var requestExtension : requestExtensions) {
                    writeBytesBigEndian16(buffer, requestExtension);
                }
            }
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + (responderIdListLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0)
                    + (requestExtensionsLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0);
        }

        @Override
        public TlsCertificateStatusResponse deserialize(ByteBuffer buffer) {
            var data = readBytesBigEndian24(buffer);
            return new TlsCertificateStatusResponse.Ocsp(data);
        }
    }

    final class OcspMulti implements TlsCertificateStatusRequest {
        private final List<byte[]> responderIdList;
        private final int responderIdListLength;
        private final List<byte[]> requestExtensions;
        private final int requestExtensionsLength;

        OcspMulti(List<byte[]> responderIdList, int responderIdListLength, List<byte[]> requestExtensions, int requestExtensionsLength) {
            this.responderIdList = responderIdList;
            this.responderIdListLength = responderIdListLength;
            this.requestExtensions = requestExtensions;
            this.requestExtensionsLength = requestExtensionsLength;
        }

        @Override
        public TlsCertificateStatusType type() {
            return TlsCertificateStatusType.OCSP_MULTI;
        }

        public List<byte[]> responderIdList() {
            return Collections.unmodifiableList(responderIdList);
        }

        public List<byte[]> requestExtensions() {
            return Collections.unmodifiableList(requestExtensions);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, type().id());
            if(responderIdListLength > 0) {
                writeBigEndianInt16(buffer, responderIdListLength);
                for(var responderId : responderIdList) {
                    writeBytesBigEndian16(buffer, responderId);
                }
            }
            if(requestExtensionsLength > 0) {
                writeBigEndianInt16(buffer, requestExtensionsLength);
                for(var requestExtension : requestExtensions) {
                    writeBytesBigEndian16(buffer, requestExtension);
                }
            }
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + (responderIdListLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0)
                    + (requestExtensionsLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0);
        }

        @Override
        public TlsCertificateStatusResponse deserialize(ByteBuffer buffer) {
            var length  = readBigEndianInt24(buffer);
            var data = new ArrayList<byte[]>();
            try(var _ = scopedRead(buffer, length)) {
                while (buffer.hasRemaining()) {
                    var entry = readBytesBigEndian24(buffer);
                    data.add(entry);
                }
            }
            return new TlsCertificateStatusResponse.OcspMulti(data, length);
        }
    }
}
