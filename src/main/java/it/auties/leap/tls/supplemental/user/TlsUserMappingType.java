package it.auties.leap.tls.supplemental.user;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.net.URI;

public final class TlsUserMappingType implements TlsIdentifiableProperty<Byte> {
    private static final TlsUserMappingType UDP_DOMAIN_HINT = new TlsUserMappingType((byte) 1);

    private final byte id;

    private TlsUserMappingType(byte id) {
        this.id = id;
    }

    public static TlsUserMappingType udpDomainHint() {
        return UDP_DOMAIN_HINT;
    }

    public static TlsUserMappingType reservedForPrivateUse(byte id) {
        if(id < -32 || id > -1) {
            throw new TlsAlert(
                    "Only values from 224-255 (decimal) inclusive are reserved for Private Use",
                    URI.create("https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-12")
            );
        }

        return new TlsUserMappingType(id);
    }

    @Override
    public Byte id() {
        return id;
    }
}
