package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsAuthorizationDataEntry extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static Optional<? extends TlsAuthorizationDataEntry> of(ByteBuffer buffer) {
        var id = readBigEndianInt8(buffer);
        return switch (id) {
            case X509AttrCert.ID -> Optional.of(X509AttrCert.of(buffer));
            case SAMLAssertion.ID -> Optional.of(SAMLAssertion.of(buffer));
            case X509AttrCertUrl.ID -> Optional.of(X509AttrCertUrl.of(buffer));
            case SAMLAssertionUrl.ID -> Optional.of(SAMLAssertionUrl.of(buffer));
            default -> Optional.empty();
        };
    }

    final class X509AttrCert implements TlsAuthorizationDataEntry {
        private static final int ID = 0;

        private final byte[] certificate;

        private X509AttrCert(byte[] certificate) {
            this.certificate = certificate;
        }

        public static X509AttrCert of(ByteBuffer buffer) {
            var cert = readBytesBigEndian16(buffer);
            return new X509AttrCert(cert);
        }

        public byte[] certificate() {
            return certificate;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytesBigEndian16(buffer, certificate);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + INT16_LENGTH + certificate.length;
        }
    }

    final class SAMLAssertion implements TlsAuthorizationDataEntry {
        private static final int ID = 1;

        private final byte[] assertion;

        private SAMLAssertion(byte[] assertion) {
            this.assertion = assertion;
        }

        public static SAMLAssertion of(ByteBuffer buffer) {
            var assertion = readBytesBigEndian16(buffer);
            return new SAMLAssertion(assertion);
        }

        public byte[] assertion() {
            return assertion;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytesBigEndian16(buffer, assertion);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + INT16_LENGTH + assertion.length;
        }
    }

    final class X509AttrCertUrl implements TlsAuthorizationDataEntry {
        private static final int ID = 2;

        private final TlsAuthorizationUrlAndHash urlAndHash;

        public static X509AttrCertUrl of(ByteBuffer buffer) {
            var assertion = TlsAuthorizationUrlAndHash.of(buffer);
            return new X509AttrCertUrl(assertion);
        }

        private X509AttrCertUrl(TlsAuthorizationUrlAndHash urlAndHash) {
            this.urlAndHash = urlAndHash;
        }

        public TlsAuthorizationUrlAndHash urlAndHash() {
            return urlAndHash;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            urlAndHash.serialize(buffer);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + urlAndHash.length();
        }
    }

    final class SAMLAssertionUrl implements TlsAuthorizationDataEntry {
        private static final int ID = 3;

        private final TlsAuthorizationUrlAndHash urlAndHash;

        private SAMLAssertionUrl(TlsAuthorizationUrlAndHash urlAndHash) {
            this.urlAndHash = urlAndHash;
        }

        public static SAMLAssertionUrl of(ByteBuffer buffer) {
            var assertion = TlsAuthorizationUrlAndHash.of(buffer);
            return new SAMLAssertionUrl(assertion);
        }

        public TlsAuthorizationUrlAndHash urlAndHash() {
            return urlAndHash;
        }

        @Override
        public Byte id() {
            return ID;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            urlAndHash.serialize(buffer);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + urlAndHash.length();
        }
    }
}
