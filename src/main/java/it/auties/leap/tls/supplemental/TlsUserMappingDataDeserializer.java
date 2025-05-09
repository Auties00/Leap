package it.auties.leap.tls.supplemental;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;

import java.nio.ByteBuffer;

public interface TlsUserMappingDataDeserializer {
    static TlsUserMappingDataDeserializer upnDomainHint() {
        return TlsUserMappingData.UpnDomainHint.DESERIALIZER;
    }

    static TlsUserMappingDataDeserializer unsupported(byte id) {
        final class Unsupported implements TlsUserMappingDataDeserializer {
            @Override
            public byte id() {
                return id;
            }

            @Override
            public TlsUserMappingData deserialize(ByteBuffer buffer) {
                throw new TlsAlert("Unsupported deserializer should not be selected", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
        }

        return new Unsupported();
    }

    byte id();
    TlsUserMappingData deserialize(ByteBuffer buffer);
}
