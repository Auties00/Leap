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
import it.auties.leap.tls.extension.TlsExtensionPayload;
import it.auties.leap.tls.group.TlsSupportedGroupKeys;
import it.auties.leap.tls.group.TlsSupportedGroup;
import it.auties.leap.tls.context.TlsContextualProperty;
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

public final class KeyShareExtension implements TlsExtension.Agnostic {
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
    public Optional<? extends TlsExtension.Server> deserializeClient(TlsContext context, int type, ByteBuffer source) {
        return deserializeClient(context, source);
    }

    private static Optional<ConfiguredServer> deserializeClient(TlsContext context, ByteBuffer buffer) {
        var supportedGroups = context.getAdvertisedValue(TlsContextualProperty.supportedGroups())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsSupportedGroup::id, Function.identity()));
        var namedGroupId = readBigEndianInt16(buffer);
        var namedGroup = supportedGroups.get(namedGroupId);
        if (namedGroup == null) {
            throw new TlsAlert("Remote tried to negotiate a key from a named group that wasn't advertised", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }
        var rawPublicKey = readBytesBigEndian16(buffer);
        var publicKey = namedGroup.parsePublicKey(rawPublicKey);
        var entry = new KeyShareEntry(
                namedGroup,
                publicKey,
                null,
                rawPublicKey
        );
        var extension = new ConfiguredServer(entry);
        return Optional.of(extension);
    }

    @Override
    public Optional<? extends Client> deserializeServer(TlsContext context, int type, ByteBuffer source) {
        return deserializeServer(context, source);
    }

    private static Optional<ConfiguredClient> deserializeServer(TlsContext context, ByteBuffer response) {
        var entries = new ArrayList<KeyShareEntry>();
        var entriesLength = response.remaining();
        var supportedGroups = context.getAdvertisedValue(TlsContextualProperty.supportedGroups())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsSupportedGroup::id, Function.identity()));
        try(var _ = scopedRead(response, entriesLength)) {
            while (response.hasRemaining()) {
                var namedGroupId = readBigEndianInt16(response);
                var namedGroup = supportedGroups.get(namedGroupId);
                if (namedGroup == null) {
                    continue;
                }

                var rawPublicKey = readBytesBigEndian16(response);
                var publicKey = namedGroup.parsePublicKey(rawPublicKey);
                var entry = new KeyShareEntry(
                        namedGroup,
                        publicKey,
                        null,
                        rawPublicKey
                );
                entries.add(entry);
            }
            var extension = new ConfiguredClient(entries, entriesLength);
            return Optional.of(extension);
        }
    }

    @Override
    public TlsExtensionPayload toPayload(TlsContext context) {
        return switch (context.localConnectionState().type()) {
            case CLIENT -> {
                var entries = new ArrayList<KeyShareEntry>();
                var entriesLength = 0;
                var supportedGroups = context.getAdvertisedValue(TlsContextualProperty.supportedGroups())
                        .orElseThrow(() -> new TlsAlert("Missing negotiable property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                for(var supportedGroup : supportedGroups) {
                    var keyPair = supportedGroup.generateKeyPair(context);
                    var publicKey = keyPair.getPublic();
                    var privateKey = keyPair.getPrivate();
                    var rawPublicKey = supportedGroup.dumpPublicKey(keyPair.getPublic());
                    var entry = new KeyShareEntry(
                            supportedGroup,
                            publicKey,
                            privateKey,
                            rawPublicKey
                    );
                    entries.add(entry);
                    entriesLength += entry.length();
                }
                yield new ConfiguredClient(entries, entriesLength);
            }
            case SERVER -> {
                var supportedGroups = context.getAdvertisedValue(TlsContextualProperty.supportedGroups())
                        .orElseThrow(() -> new TlsAlert("Missing negotiable property: supportedGroups", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
                if(supportedGroups.isEmpty()) {
                    throw new TlsAlert("No named groups", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
                }
                var supportedGroup = supportedGroups.getFirst();
                var keyPair = supportedGroup.generateKeyPair(context);
                var publicKey = keyPair.getPublic();
                var privateKey = keyPair.getPrivate();
                var rawPublicKey = supportedGroup.dumpPublicKey(keyPair.getPublic());
                var entry = new KeyShareEntry(
                        supportedGroup,
                        publicKey,
                        privateKey,
                        rawPublicKey
                );
                yield new ConfiguredServer(entry);
            }
        };
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.some(SUPPORTED_GROUPS_TYPE);
    }

    private record ConfiguredClient(
            List<KeyShareEntry> entries,
            int entriesLength
    ) implements TlsExtension.Client, TlsExtensionPayload {
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
                        localState.addEphemeralKeyPair(entry.toKeys());
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
                        remoteState.addEphemeralKeyPair(entry.toKeys());
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
        public Optional<ConfiguredServer> deserializeClient(TlsContext context, int type, ByteBuffer source) {
            return KeyShareExtension.deserializeClient(context, source);
        }

        @Override
        public Optional<ConfiguredClient> deserializeServer(TlsContext context, int type, ByteBuffer source) {
            return KeyShareExtension.deserializeServer(context, source);
        }

        @Override
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
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

    private record ConfiguredServer(
            KeyShareEntry entry
    ) implements TlsExtension.Server, TlsExtensionPayload {
        @Override
        public void serializePayload(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, entry.length());
            entry.serialize(buffer);
        }

        @Override
        public void apply(TlsContext context, TlsSource source) {
            switch (source) {
                case LOCAL -> {
                    var localState = context.localConnectionState();
                    localState.addEphemeralKeyPair(entry.toKeys());
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
                    remoteState.addEphemeralKeyPair(entry.toKeys());
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
            if(state.chooseEphemeralKeyPair(entry.namedGroup())) {
                return entry.namedGroup();
            }

            throw new TlsAlert("There isn't a proposed key share that matches an advertised supported group", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        @Override
        public Optional<ConfiguredServer> deserializeClient(TlsContext context, int type, ByteBuffer source) {
            return KeyShareExtension.deserializeClient(context, source);
        }

        @Override
        public Optional<ConfiguredClient> deserializeServer(TlsContext context, int type, ByteBuffer source) {
            return KeyShareExtension.deserializeServer(context, source);
        }

        @Override
        public int payloadLength() {
            return INT16_LENGTH + entry.length();
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
        public TlsExtensionPayload toPayload(TlsContext context) {
            return this;
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
        public void serialize(ByteBuffer buffer) {
            writeBigEndianInt16(buffer, namedGroup.id());
            writeBytesBigEndian16(buffer, rawPublicKey);
        }

        public int length() {
            return INT16_LENGTH + INT16_LENGTH + rawPublicKey.length;
        }

        public TlsSupportedGroupKeys toKeys() {
            return TlsSupportedGroupKeys.of(namedGroup, publicKey, privateKey);
        }
    }
}
