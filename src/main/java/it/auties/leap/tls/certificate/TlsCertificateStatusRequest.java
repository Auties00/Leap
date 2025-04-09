package it.auties.leap.tls.certificate;

import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsCertificateStatusRequest extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty permits TlsCertificateStatusRequest.OCSP {
    static OCSP ocsp(List<byte[]> responderId, List<byte[]> requestExtensions) {
        if(responderId == null) {
            throw new NullPointerException("responderId");
        }

        if(requestExtensions == null) {
            throw new NullPointerException("requestExtensions");
        }

        var responderIdLength = responderId.stream()
                .mapToInt(bytes -> INT16_LENGTH + bytes.length)
                .sum();
        var requestExtensionsLength = requestExtensions.stream()
                .mapToInt(bytes -> INT16_LENGTH + bytes.length)
                .sum();
        return new OCSP(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
    }

    @SuppressWarnings("SwitchStatementWithTooFewBranches")
    static Optional<? extends TlsCertificateStatusRequest> of(ByteBuffer buffer) {
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

    final class OCSP implements TlsCertificateStatusRequest {
        private static final int ID = 1;

        private final List<byte[]> responderIdList;
        private final int responderIdListLength;
        private final List<byte[]> requestExtensions;
        private final int requestExtensionsLength;

        private OCSP(List<byte[]> responderIdList, int responderIdListLength, List<byte[]> requestExtensions, int requestExtensionsLength) {
            this.responderIdList = responderIdList;
            this.responderIdListLength = responderIdListLength;
            this.requestExtensions = requestExtensions;
            this.requestExtensionsLength = requestExtensionsLength;
        }

        public static OCSP of(ByteBuffer buffer) {
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

            return new OCSP(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
        }

        @Override
        public Byte id() {
            return ID;
        }

        public List<byte[]> responderIdList() {
            return Collections.unmodifiableList(responderIdList);
        }

        public List<byte[]> requestExtensions() {
            return Collections.unmodifiableList(requestExtensions);
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsCertificateStatusRequest.super.serialize(buffer);
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
            return TlsCertificateStatusRequest.super.length()
                    + (responderIdListLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0)
                    + (requestExtensionsLength > 0 ? INT16_LENGTH + requestExtensionsLength : 0);
        }
    }
}
