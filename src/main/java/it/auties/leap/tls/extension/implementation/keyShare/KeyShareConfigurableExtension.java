package it.auties.leap.tls.extension.implementation.keyShare;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.extension.TlsConfigurableClientExtension;
import it.auties.leap.tls.extension.TlsConfigurableServerExtension;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.version.TlsVersion;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class KeyShareConfigurableExtension implements TlsConfigurableClientExtension, TlsConfigurableServerExtension {
    private static final KeyShareConfigurableExtension INSTANCE = new KeyShareConfigurableExtension();
    
    private KeyShareConfigurableExtension() {
        
    }

    public static KeyShareConfigurableExtension instance() {
        return INSTANCE;
    }

    @Override
    public int extensionType() {
        return KEY_SHARE_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return KEY_SHARE_VERSIONS;
    }
    
    @Override
    public boolean equals(Object o) {
        return o instanceof KeyShareConfigurableExtension;
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
    public Optional<? extends TlsConfiguredClientExtension> configure(TlsContext context, int messageLength) {
        var entries = new ArrayList<KeyShareEntry>();
        var entriesLength = 0;
        var supportedGroups = context.getNegotiableValue(TlsProperty.supportedGroups())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.supportedGroups()));
        for(var supportedGroup : supportedGroups) {
            var keyPair = supportedGroup.generateLocalKeyPair(context);
            var publicKey = supportedGroup.dumpPublicKey(keyPair.getPublic());
            var entry = new KeyShareEntry(supportedGroup.id(), publicKey);
            entries.add(entry);
            entriesLength += entry.length();
        }
        return Optional.of(new KeyShareExtension(entries, entriesLength));
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.some(SUPPORTED_GROUPS_TYPE);
    }
}
