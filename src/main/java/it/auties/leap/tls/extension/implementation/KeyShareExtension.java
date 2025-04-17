package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.connection.TlsConnection;
import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.group.TlsKeyPair;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class KeyShareExtension implements TlsExtension.Configurable {
    private static final KeyShareExtension INSTANCE = new KeyShareExtension();
    
    private KeyShareExtension() {
        
    }

    public static KeyShareExtension instance() {
        return INSTANCE;
    }

    @Override
    public int type() {
        return KEY_SHARE_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return KEY_SHARE_VERSIONS;
    }
    
    @Override
    public boolean equals(Object o) {
        return o instanceof KeyShareExtension;
    }

    @Override
    public int hashCode() {
        return 1;
    }

    @Override
    public String toString() {
        return "KeyShareExtension[" +
                "entries=" + "<configurable>" +
                ']';
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Client> configureClient(TlsContext context, int messageLength) {
        return configure(context);
    }

    @Override
    public Optional<? extends TlsExtension.Configured.Server> configureServer(TlsContext context, int messageLength) {
        return configure(context);
    }

    private Optional<? extends TlsExtension.Configured.Agnostic> configure(TlsContext context) {
        var entries = new ArrayList<KeyShareEntry>();
        var entriesLength = 0;
        var supportedGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: " + TlsProperty.supportedGroups().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        for(var supportedGroup : supportedGroups) {
            var keyPair = supportedGroup.generateKeyPair(context);
            var entry = new KeyShareEntry(supportedGroup, keyPair.getPublic(), keyPair.getPrivate());
            entries.add(entry);
            entriesLength += entry.length();
        }
        return Optional.of(new Configured(entries, entriesLength));
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.some(SUPPORTED_GROUPS_TYPE);
    }

    private record Configured(
            List<KeyShareEntry> entries,
            int entriesLength
    ) implements TlsExtension.Configured.Agnostic {
        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, entriesLength);
            for (var entry : entries) {
                entry.serialize(buffer);
            }
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            switch (source) {
                case LOCAL -> {
                    var localState = context.localConnectionState();
                    for(var entry : entries) {
                        localState.addEphemeralKeyPair(TlsKeyPair.of(entry.namedGroup(), entry.publicKey(), entry.privateKey()));
                    }
                    if(localState.type() == TlsConnectionType.SERVER) {
                        var selectedGroup = chooseGroup(localState);
                        localState.chooseEphemeralKeyPair(selectedGroup);
                        context.remoteConnectionState()
                                .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                                .chooseEphemeralKeyPair(selectedGroup);
                    }
                }

                case REMOTE -> {
                    var remoteState = context.remoteConnectionState()
                            .orElseThrow(() -> new TlsAlert("No remote connection state was created", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                    for(var entry : entries) {
                        remoteState.addEphemeralKeyPair(TlsKeyPair.of(entry.namedGroup(), entry.publicKey(), entry.privateKey()));
                    }
                    if(remoteState.type() == TlsConnectionType.SERVER) {
                        var selectedGroup = chooseGroup(remoteState);
                        context.localConnectionState()
                                .chooseEphemeralKeyPair(selectedGroup);
                        remoteState.chooseEphemeralKeyPair(selectedGroup);
                    }
                }
            }
        }

        private TlsSupportedGroup chooseGroup(TlsConnection state) {
            if(entries.isEmpty()) {
                // TODO: Needs renegotiation
                throw new UnsupportedOperationException();
            }

            for(var entry : entries) {
                if(state.chooseEphemeralKeyPair(entry.namedGroup())) {
                    return entry.namedGroup();
                }
            }

            throw new TlsAlert("There isn't a proposed key share that matches an advertised supported group", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        @Override
        public Optional<KeyShareExtension.Configured> deserialize(TlsContext context, int type, ByteBuffer buffer) {
            var entries = new ArrayList<KeyShareEntry>();
            var entriesSize = buffer.remaining();
            var supportedGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                    .orElseThrow(() -> {
                        throw new TlsAlert("Missing negotiable property: " + TlsProperty.supportedGroups().id(), TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                    })
                    .stream()
                    .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
            while (buffer.hasRemaining()) {
                var namedGroupId = readBigEndianInt16(buffer);
                var namedGroup = supportedGroups.get(namedGroupId);
                if(namedGroup != null) {
                    var rawPublicKey = readBytesBigEndian16(buffer);
                    var publicKey = namedGroup.parsePublicKey(rawPublicKey);
                    var entry = new KeyShareEntry(namedGroup, publicKey, null, rawPublicKey);
                    entries.add(entry);
                }else if (context.localConnectionState().type() == TlsConnectionType.CLIENT) {
                    throw new TlsAlert("Remote tried to negotiate a key from a named group that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
                }
            }
            if(context.localConnectionState().type() == TlsConnectionType.CLIENT && entries.size() > 1) {
                throw new TlsAlert("Remote tried to negotiate too many keys", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
            }
            var extension = new KeyShareExtension.Configured(entries, entriesSize);
            return Optional.of(extension);
        }

        @Override
        public int payloadLength() {
            return INT16_LENGTH + entriesLength;
        }

        @Override
        public int type() {
            return KEY_SHARE_TYPE;
        }

        @Override
        public List<TlsVersion> versions() {
            return KEY_SHARE_VERSIONS;
        }

        @Override
        public TlsExtensionDependencies dependencies() {
            return TlsExtensionDependencies.none();
        }
    }

    private record KeyShareEntry(
            TlsSupportedGroup namedGroup,
            PublicKey publicKey,
            PrivateKey privateKey,
            byte[] rawPublicKey
    ) {
        private KeyShareEntry(TlsSupportedGroup namedGroup, PublicKey publicKey, PrivateKey privateKey) {
            this(namedGroup, publicKey, privateKey, namedGroup.dumpPublicKey(publicKey));
        }

        private void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, namedGroup.id());
            writeBytesBigEndian16(buffer, rawPublicKey);
        }

        private int length() {
            return INT16_LENGTH + INT16_LENGTH + rawPublicKey.length;
        }
    }
}
