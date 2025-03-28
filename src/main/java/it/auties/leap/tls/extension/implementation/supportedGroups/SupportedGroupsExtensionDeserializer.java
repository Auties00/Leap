package it.auties.leap.tls.extension.implementation.supportedGroups;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;

final class SupportedGroupsExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new SupportedGroupsExtensionDeserializer();

    private SupportedGroupsExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var groupsSize = readBigEndianInt16(buffer);
        var groups = new ArrayList<TlsSupportedGroup>(groupsSize);
        var knownGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.ecPointsFormats()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        for (var i = 0; i < groupsSize; i++) {
            var groupId = readBigEndianInt16(buffer);
            var group = knownGroups.get(groupId);
            if(group != null) {
                groups.add(group);
            }else if(mode == TlsContextMode.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a supported group that wasn't advertised");
            }
        }
        var extension = new SupportedGroupsExtension(groups);
        return Optional.of(extension);
    }
}
