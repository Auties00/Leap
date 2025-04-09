package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.certificate.TlsCertificateStatusRequest;
import it.auties.leap.tls.certificate.TlsCertificateStatusResponse;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.supplemental.TlsSupplementalDataFormats;
import it.auties.leap.tls.supplemental.user.TlsUserMappingData;
import it.auties.leap.tls.util.BufferUtils;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferUtils.*;

public record UserMappingTypesExtension(
        List<TlsUserMappingData> userMappings,
        int userMappingsLength
) implements TlsExtension.Configured.Agnostic {
    public UserMappingTypesExtension(List<TlsUserMappingData> userMappings) {
        var userMappingsLength = userMappings.stream()
                .mapToInt(TlsUserMappingData::length)
                .sum();
        this(userMappings, userMappingsLength);
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {
        if(userMappingsLength > 0) {
            writeBigEndianInt8(buffer, userMappingsLength);
            for(var userMapping : userMappings) {
                userMapping.serialize(buffer);
            }
        }
    }

    @Override
    public int payloadLength() {
        return userMappingsLength > 0 ? INT8_LENGTH + userMappingsLength : 0;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public Optional<UserMappingTypesExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var userMappings = new ArrayList<TlsUserMappingData>();
        var userMappingsLength = readBigEndianInt8(buffer);
        try(var _ = scopedRead(buffer, userMappingsLength)) {
           while (buffer.hasRemaining()) {
               var userMapping = TlsUserMappingData.of(buffer);
               userMappings.add(userMapping);
           }
        }
        var extension = new UserMappingTypesExtension(userMappings, userMappingsLength);
        return Optional.of(extension);
    }

    @Override
    public int type() {
        return USER_MAPPING_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return USER_MAPPING_VERSIONS;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}