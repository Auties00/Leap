package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsUserMappingData {
    static UpnDomainHint upnDomainHint(byte[] userPrincipalName, byte[] domainName) {
        if (userPrincipalName == null) {
            throw new TlsAlert("userPrincipalName", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }

        if(domainName == null) {
            throw new TlsAlert("domainName", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }

        return new UpnDomainHint(userPrincipalName, domainName);
    }

    byte id();
    Type type();
    void serialize(ByteBuffer buffer);
    int length();
    TlsUserMappingDataDeserializer deserializer();

    final class UpnDomainHint implements TlsUserMappingData {
        private static final byte ID = 1;
        static final TlsUserMappingDataDeserializer DESERIALIZER = new TlsUserMappingDataDeserializer() {
            @Override
            public TlsUserMappingData deserialize(ByteBuffer buffer) {
                var userPrincipalName = readBytesBigEndian16(buffer);
                var domainName = readBytesBigEndian16(buffer);
                return new UpnDomainHint(userPrincipalName, domainName);
            }

            @Override
            public byte id() {
                return ID;
            }
        };

        private final byte[] userPrincipalName;
        private final byte[] domainName;

        private UpnDomainHint(byte[] userPrincipalName, byte[] domainName) {
            this.userPrincipalName = userPrincipalName;
            this.domainName = domainName;
        }

        @Override
        public byte id() {
            return ID;
        }

        @Override
        public TlsUserMappingDataDeserializer deserializer() {
            return DESERIALIZER;
        }

        @Override
        public Type type() {
            return Type.UPN_DOMAIN_HINT;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            writeBytesBigEndian16(buffer, userPrincipalName);
            writeBytesBigEndian16(buffer, domainName);
        }

        @Override
        public int length() {
            return INT8_LENGTH
                    + INT16_LENGTH + userPrincipalName.length
                    + INT16_LENGTH + domainName.length;
        }
    }

    non-sealed abstract class Reserved implements TlsUserMappingData {
        private final byte id;

        protected Reserved(byte id) {
            if(id < -32 || id > -1) {
                throw new IllegalArgumentException("Only values from 224-255 (decimal) inclusive are reserved for Private Use");
            }

            this.id = id;
        }

        @Override
        public final byte id() {
            return id;
        }

        @Override
        public final Type type() {
            return Type.RESERVED_FOR_PRIVATE_USE;
        }
    }

    enum Type {
        UPN_DOMAIN_HINT,
        RESERVED_FOR_PRIVATE_USE
    }
}
