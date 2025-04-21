package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsCertificateStatus extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    Type type();
    TlsCertificateStatus deserialize(ByteBuffer buffer);

    sealed interface Request extends TlsCertificateStatus {
        static Ocsp ocsp(List<byte[]> responderId, List<byte[]> requestExtensions) {
            checkOcsp(responderId, requestExtensions);
            var responderIdLength = getInt16ByteArrayLength(responderId);
            var requestExtensionsLength = getInt16ByteArrayLength(requestExtensions);
            return new Ocsp(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
        }

        static OcspMulti ocspMulti(List<byte[]> responderId, List<byte[]> requestExtensions) {
            checkOcsp(responderId, requestExtensions);
            var responderIdLength = getInt16ByteArrayLength(responderId);
            var requestExtensionsLength = getInt16ByteArrayLength(requestExtensions);
            return new OcspMulti(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
        }

        private static void checkOcsp(List<byte[]> responderId, List<byte[]> requestExtensions) {
            if (responderId == null) {
                throw new TlsAlert("Responder id cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }

            if (requestExtensions == null) {
                throw new TlsAlert("Request extensions cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }

        private static int getInt16ByteArrayLength(List<byte[]> requestExtensions) {
            return requestExtensions
                    .stream()
                    .mapToInt(bytes -> INT16_LENGTH + bytes.length)
                    .sum();
        }

        @Override
        Response deserialize(ByteBuffer buffer);

        final class Ocsp implements Request {
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
            public Type type() {
                return Type.OCSP;
            }

            public List<byte[]> responderIdList() {
                return Collections.unmodifiableList(responderIdList);
            }

            public List<byte[]> requestExtensions() {
                return Collections.unmodifiableList(requestExtensions);
            }

            @Override
            public Byte id() {
                return 1;
            }

            @SuppressWarnings("DuplicatedCode")
            @Override
            public void serialize(ByteBuffer buffer) {
                writeBigEndianInt8(buffer, id());
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
            public Response deserialize(ByteBuffer buffer) {
                var data = readBytesBigEndian24(buffer);
                return new Response.Ocsp(data);
            }
        }

        final class OcspMulti implements Request {
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
            public Type type() {
                return Type.OCSP_MULTI;
            }

            public List<byte[]> responderIdList() {
                return Collections.unmodifiableList(responderIdList);
            }

            public List<byte[]> requestExtensions() {
                return Collections.unmodifiableList(requestExtensions);
            }

            @Override
            public Byte id() {
                return 2;
            }

            @SuppressWarnings("DuplicatedCode")
            @Override
            public void serialize(ByteBuffer buffer) {
                writeBigEndianInt8(buffer, id());
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
            public Response deserialize(ByteBuffer buffer) {
                var length  = readBigEndianInt24(buffer);
                var data = new ArrayList<byte[]>();
                try(var _ = scopedRead(buffer, length)) {
                    while (buffer.hasRemaining()) {
                        var entry = readBytesBigEndian24(buffer);
                        data.add(entry);
                    }
                }
                return new Response.OcspMulti(data, length);
            }
        }
    }

    sealed interface Response extends TlsCertificateStatus {
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

        @Override
        Request deserialize(ByteBuffer buffer);

        final class Ocsp implements Response {
            private final byte[] data;

            Ocsp(byte[] data) {
                this.data = data;
            }

            @Override
            public Type type() {
                return Type.OCSP;
            }

            public byte[] data() {
                return data;
            }

            @Override
            public Byte id() {
                return 1;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                writeBigEndianInt8(buffer, id());
                writeBytesBigEndian24(buffer, data);
            }

            @Override
            public int length() {
                return INT8_LENGTH
                        + INT24_LENGTH + data.length;
            }

            @SuppressWarnings("DuplicatedCode")
            @Override
            public Request deserialize(ByteBuffer buffer) {
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

                return new Request.Ocsp(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
            }
        }

        final class OcspMulti implements Response {
            private final List<byte[]> data;
            private final int length;

            OcspMulti(List<byte[]> data, int length) {
                this.data = data;
                this.length = length;
            }

            @Override
            public Byte id() {
                return 2;
            }

            @Override
            public Type type() {
                return Type.OCSP_MULTI;
            }

            public List<byte[]> data() {
                return data;
            }

            @Override
            public void serialize(ByteBuffer buffer) {
                writeBigEndianInt8(buffer, id());
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

            @SuppressWarnings("DuplicatedCode")
            @Override
            public Request deserialize(ByteBuffer buffer) {
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

                return new Request.OcspMulti(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
            }
        }
    }

    //   https://datatracker.ietf.org/doc/rfc6961/
    //   Section 2.1 defines the new TLS extension status_request_v2 (17)
    //   enum, which has been added to the "ExtensionType Values" list in the
    //   IANA "Transport Layer Security (TLS) Extensions" registry.
    //
    //   Section 2.2 describes a TLS CertificateStatusType registry that is
    //   now maintained by IANA.  The "TLS Certificate Status Types" registry
    //   has been created under the "Transport Layer Security (TLS)
    //   Extensions" registry.  CertificateStatusType values are to be
    //   assigned via IETF Review as defined in [RFC5226].  The initial
    //   registry corresponds to the definition of "CertificateStatusType" in
    //   Section 2.2.
    //
    //   Value   Description   Reference
    //   -----------------------------------------
    //   0       Reserved      [RFC6961]
    //   1       ocsp          [RFC6066] [RFC6961]
    //   2       ocsp_multi    [RFC6961]
    //   3-255   Unassigned
    enum Type {
        OCSP,
        OCSP_MULTI
    }
}
