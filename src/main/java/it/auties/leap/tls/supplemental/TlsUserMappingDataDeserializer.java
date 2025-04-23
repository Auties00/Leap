package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.nio.ByteBuffer;

public interface TlsUserMappingDataDeserializer extends TlsIdentifiableProperty<Byte> {
    static TlsUserMappingDataDeserializer upnDomainHint() {
        return TlsUserMappingData.UpnDomainHint.DESERIALIZER;
    }

    static TlsUserMappingDataDeserializer unsupported(byte id) {
        final class Unsupported implements TlsUserMappingDataDeserializer {
            @Override
            public Byte id() {
                return id;
            }

            @Override
            public TlsUserMappingData deserialize(ByteBuffer buffer) {
                throw new TlsAlert("Unsupported deserializer should not be selected", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }

        return new Unsupported();
    }

    TlsUserMappingData deserialize(ByteBuffer buffer);
}
