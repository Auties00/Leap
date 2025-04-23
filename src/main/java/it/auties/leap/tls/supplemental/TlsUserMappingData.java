package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public sealed interface TlsUserMappingData extends TlsIdentifiableProperty<Byte>, TlsSerializableProperty {
    static UpnDomainHint upnDomainHint(byte[] userPrincipalName, byte[] domainName) {
        if (userPrincipalName == null) {
            throw new TlsAlert("userPrincipalName", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }

        if(domainName == null) {
            throw new TlsAlert("domainName", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }

        return new UpnDomainHint(userPrincipalName, domainName);
    }

    static Reserved reservedForPrivateUse(byte id) {
        if(id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        return new Reserved(id, null, TlsUserMappingDataDeserializer.unsupported(id));
    }

    static Reserved reservedForPrivateUse(byte id, TlsSerializableProperty payload, TlsUserMappingDataDeserializer deserializer) {
        if(id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        if(deserializer == null) {
            throw new TlsAlert(
                    "No deserializer was provided",
                    TlsAlertLevel.FATAL,
                    TlsAlertType.INTERNAL_ERROR
            );
        }

        return new Reserved(id, payload, deserializer);
    }

    Type type();
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
            public Byte id() {
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
        public Byte id() {
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

    final class Reserved implements TlsUserMappingData {
        private final byte id;
        private final TlsSerializableProperty payload;
        private final TlsUserMappingDataDeserializer deserializer;

        private Reserved(byte id, TlsSerializableProperty payload, TlsUserMappingDataDeserializer deserializer) {
            this.id = id;
            this.payload = payload;
            this.deserializer = deserializer;
        }

        @Override
        public Byte id() {
            return id;
        }

        @Override
        public TlsUserMappingDataDeserializer deserializer() {
            return deserializer;
        }

        @Override
        public Type type() {
            return Type.RESERVED_FOR_PRIVATE_USE;
        }

        @Override
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt8(buffer, id());
            if(payload != null) {
                payload.serialize(buffer);
            }
        }

        @Override
        public int length() {
            if(payload == null) {
                return INT8_LENGTH;
            }else {
                return INT8_LENGTH + payload.length();
            }
        }
    }

    enum Type {
        UPN_DOMAIN_HINT,
        RESERVED_FOR_PRIVATE_USE
    }
}
