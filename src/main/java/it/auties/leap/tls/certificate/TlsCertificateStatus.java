package it.auties.leap.tls.certificate;

import java.nio.ByteBuffer;
import java.util.*;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsCertificateStatus {
    byte id();
    Type type();
    void serialize(ByteBuffer buffer);
    int length();

    sealed interface Request extends TlsCertificateStatus {
        static Ocsp ocsp(List<byte[]> responderId, List<byte[]> requestExtensions) {
            Objects.requireNonNull(responderId, "Responder id cannot be null");
            Objects.requireNonNull(requestExtensions, "Request extensions cannot be null");
            var responderIdLength = getInt16ByteArrayLength(responderId);
            var requestExtensionsLength = getInt16ByteArrayLength(requestExtensions);
            return new Ocsp(responderId, responderIdLength, requestExtensions, requestExtensionsLength);
        }

        static OcspMulti ocspMulti(List<byte[]> responderId, List<byte[]> requestExtensions) {
            Objects.requireNonNull(responderId, "Responder id cannot be null");
            Objects.requireNonNull(requestExtensions, "Request extensions cannot be null");
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

        static Optional<? extends Request> of(ByteBuffer buffer) {
            var type = readBigEndianInt8(buffer);
            return switch(type) {
                case Ocsp.ID -> Optional.of(Ocsp.of(buffer));
                case OcspMulti.ID -> Optional.of(OcspMulti.of(buffer));
                default -> Optional.empty();
            };
        }

        final class Ocsp implements Request {
            private static final int ID = 1;

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

            public static Ocsp of(ByteBuffer buffer) {
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

                return new Ocsp(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
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
            public byte id() {
                return ID;
            }

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
        }

        final class OcspMulti implements Request {
            private static final int ID = 2;

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

            public static OcspMulti of(ByteBuffer buffer) {
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

                return new OcspMulti(responderIdList, responderIdLength, requestExtensions, requestExtensionsLength);
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
            public byte id() {
                return ID;
            }

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
        }
    }

    sealed interface Response extends TlsCertificateStatus {
        static Ocsp ocsp(byte[] data) {
            Objects.requireNonNull(data, "Data cannot be null");
            return new Ocsp(data);
        }

        static OcspMulti ocspMulti(List<byte[]> data) {
            Objects.requireNonNull(data, "Data cannot be null");
            var length = data.stream()
                    .mapToInt(entry -> INT16_LENGTH + entry.length)
                    .sum();
            return new OcspMulti(data, length);
        }

        static Optional<? extends Response> of(ByteBuffer buffer) {
            var type = readBigEndianInt8(buffer);
            return switch(type) {
                case Request.Ocsp.ID -> Optional.of(Ocsp.of(buffer));
                case Request.OcspMulti.ID -> Optional.of(OcspMulti.of(buffer));
                default -> Optional.empty();
            };
        }

        final class Ocsp implements Response {
            private final byte[] data;

            Ocsp(byte[] data) {
                this.data = data;
            }

            public static Ocsp of(ByteBuffer buffer) {
                var data = readBytesBigEndian24(buffer);
                return new Response.Ocsp(data);
            }

            @Override
            public Type type() {
                return Type.OCSP;
            }

            public byte[] data() {
                return data;
            }

            @Override
            public byte id() {
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
        }

        final class OcspMulti implements Response {
            private final List<byte[]> data;
            private final int length;

            OcspMulti(List<byte[]> data, int length) {
                this.data = data;
                this.length = length;
            }

            public static OcspMulti of(ByteBuffer buffer) {
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

            @Override
            public byte id() {
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
