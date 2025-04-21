package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsCertificateTrustedAuthorities implements TlsSerializableProperty {
    private final List<TlsCertificateTrustedAuthority> trustedAuthoritiesList;
    private final int trustedAuthoritiesLength;

    private TlsCertificateTrustedAuthorities(List<TlsCertificateTrustedAuthority> trustedAuthoritiesList, int trustedAuthoritiesLength) {
        this.trustedAuthoritiesList = trustedAuthoritiesList;
        this.trustedAuthoritiesLength = trustedAuthoritiesLength;
    }

    public static TlsCertificateTrustedAuthorities of(List<TlsCertificateTrustedAuthority> trustedAuthoritiesList) {
        if (trustedAuthoritiesList == null) {
            throw new TlsAlert("Trusted authorities cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var length = trustedAuthoritiesList.stream()
                .mapToInt(TlsSerializableProperty::length)
                .sum();
        return new TlsCertificateTrustedAuthorities(trustedAuthoritiesList, length);
    }

    public static TlsCertificateTrustedAuthorities of(TlsContext context, ByteBuffer buffer) {
        var negotiableTrustedCAs = context.getNegotiableValue(TlsProperty.trustedCA());
        if(negotiableTrustedCAs.isEmpty()) {
            throw new TlsAlert("Trusted CAs aren't negotiable", TlsAlertLevel.FATAL, TlsAlertType.HANDSHAKE_FAILURE);
        }

        var trustedAuthoritiesLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
        var trustedAuthoritiesList = new ArrayList<TlsCertificateTrustedAuthority>();
        var advertisedAuthoritiesTypesToDeserializer = negotiableTrustedCAs.get()
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsCertificateTrustedAuthority::id, Function.identity()));
        try(var _ = scopedRead(buffer, trustedAuthoritiesLength)) {
            while (buffer.hasRemaining()) {
                var typeId = readBigEndianInt8(buffer);
                var deserializer = advertisedAuthoritiesTypesToDeserializer.get(typeId);
                if(deserializer != null) {
                    var entry = deserializer.deserialize(buffer);
                    trustedAuthoritiesList.add(entry);
                }else if(context.localConnectionState().type() == TlsConnectionType.CLIENT) {
                    throw new TlsAlert("Remote sent a CA type that wasn't advertised: " + typeId, TlsAlertLevel.FATAL, TlsAlertType.HANDSHAKE_FAILURE);
                }
            }
        }
        return new TlsCertificateTrustedAuthorities(trustedAuthoritiesList, trustedAuthoritiesLength);
    }

    public List<TlsCertificateTrustedAuthority> trustedAuthoritiesList() {
        return trustedAuthoritiesList;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        if(trustedAuthoritiesLength > 0) {
            writeBigEndianInt16(buffer, trustedAuthoritiesLength);
            for (var trustedAuthority : trustedAuthoritiesList) {
                trustedAuthority.serialize(buffer);
            }
        }
    }

    @Override
    public int length() {
        if(trustedAuthoritiesLength > 0) {
            return INT16_LENGTH
                    + trustedAuthoritiesLength;
        }else {
            return 0;
        }
    }
}
