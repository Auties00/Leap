package it.auties.leap.tls.supplemental.user;

import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsUserMappingData extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static UpnDomainHint upnDomainHint(byte[] userPrincipalName, byte[] domainName) {
        if (userPrincipalName == null) {
            throw new NullPointerException("userPrincipalName");
        }

        if(domainName == null) {
            throw new NullPointerException("domainName");
        }

        return new UpnDomainHint(userPrincipalName, domainName);
    }

    @Override
    default Byte id() {
        return type().id();
    }

    TlsUserMappingType type();

    @Override
    default void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, id());
    }

    @Override
    default int length() {
        return INT8_LENGTH;
    }

    final class UpnDomainHint implements TlsUserMappingData {
        private final byte[] userPrincipalName;
        private final byte[] domainName;

        private UpnDomainHint(byte[] userPrincipalName, byte[] domainName) {
            this.userPrincipalName = userPrincipalName;
            this.domainName = domainName;
        }

        @Override
        public Byte id() {
            return 1;
        }

        @Override
        public TlsUserMappingType type() {
            return TlsUserMappingType.udpDomainHint();
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            TlsUserMappingData.super.serialize(buffer);
            writeBytesBigEndian16(buffer, userPrincipalName);
            writeBytesBigEndian16(buffer, domainName);
        }

        @Override
        public int length() {
            return TlsUserMappingData.super.length()
                    + INT16_LENGTH + userPrincipalName.length
                    + INT16_LENGTH + domainName.length;
        }
    }

    non-sealed class Reserved implements TlsUserMappingData {
        protected final TlsUserMappingType type;

        protected Reserved(byte id) {
            this.type = type;
        }

        @Override
        public final TlsUserMappingType type() {
            return type;
        }
    }
}
