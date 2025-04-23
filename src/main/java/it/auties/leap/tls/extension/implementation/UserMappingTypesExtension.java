package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.supplemental.TlsUserMappingData;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

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
        var connection = switch (source) {
            case LOCAL -> context.localConnectionState();
            case REMOTE -> context.remoteConnectionState()
                    .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        };
        var userMappingsDeserializers = userMappings.stream()
                .map(TlsUserMappingData::deserializer)
                .toList();
        switch (connection.type()) {
            case CLIENT -> context.addNegotiableProperty(TlsProperty.userMappings(), userMappingsDeserializers);
            case SERVER -> context.addNegotiatedProperty(TlsProperty.userMappings(), userMappingsDeserializers);
        }
    }

    @Override
    public Optional<UserMappingTypesExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var userMappingsTypeToDeserializer = context.getNegotiableValue(TlsProperty.userMappings())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: userMappings", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var userMappings = new ArrayList<TlsUserMappingData>();
        var userMappingsLength = readBigEndianInt8(buffer);
        try(var _ = scopedRead(buffer, userMappingsLength)) {
           while (buffer.hasRemaining()) {
               var userMappingType = readBigEndianInt8(buffer);
               var userMappingDeserializer = userMappingsTypeToDeserializer.get(userMappingType);
               if(userMappingDeserializer != null) {
                   var userMapping = userMappingDeserializer.deserialize(buffer);
                   userMappings.add(userMapping);
               } else if(context.localConnectionState().type() == TlsConnectionType.CLIENT) {
                   throw new TlsAlert("Remote tried to negotiate a user mapping type that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
               }
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