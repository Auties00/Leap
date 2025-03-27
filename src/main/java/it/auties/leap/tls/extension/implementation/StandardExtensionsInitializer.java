package it.auties.leap.tls.extension.implementation;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.extension.*;
import it.auties.leap.tls.property.TlsProperty;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;

public final class StandardExtensionsInitializer implements TlsExtensionsInitializer {
    private static final StandardExtensionsInitializer INSTANCE = new StandardExtensionsInitializer();

    private StandardExtensionsInitializer() {

    }

    public static StandardExtensionsInitializer instance() {
        return INSTANCE;
    }

    @Override
    public TlsExtensions process(TlsContext context) {
        var extensions = context.getNegotiableValue(TlsProperty.extensions())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.extensions()));
        var supportedVersions = context.getNegotiableValue(TlsProperty.version())
                .map(HashSet::new)
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.version()));

        var dependenciesTree = new LinkedHashMap<Integer, TlsExtension>();
        for (var extension : extensions) {
            if (supportedVersions.stream().anyMatch(version -> extension.versions().contains(version))) {
                var conflict = dependenciesTree.put(extension.extensionType(), extension);
                if (conflict != null) {
                    throw new IllegalArgumentException("Extension with type %s defined by <%s> conflicts with an extension processed previously with type %s defined by <%s>".formatted(
                            extension.extensionType(),
                            extension.getClass().getName(),
                            extension.extensionType(),
                            conflict.getClass().getName()
                    ));
                }
            }
        }

        var results = new ArrayList<TlsConcreteExtension>(dependenciesTree.size());
        var length = 0;

        var deferred = new ArrayList<TlsConfigurableExtension>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsConcreteExtension concrete -> results.add(concrete);
                case TlsConfigurableExtension configurableExtension -> {
                    switch (configurableExtension.dependencies()) {
                        case TlsExtensionDependencies.None _ -> {
                           var result = configurableExtension.newInstance(context, length);
                           if(result.isPresent()) {
                               results.add(result.get());
                               length += result.get().extensionLength();
                           }
                        }

                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for(var dependency : some.includedTypes()) {
                                if(dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if(conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            }else {
                                var result = configurableExtension.newInstance(context, length);
                                if(result.isPresent()) {
                                    results.add(result.get());
                                    length += result.get().extensionLength();
                                }
                            }
                        }

                        case TlsExtensionDependencies.All _ -> deferred.add(configurableExtension);
                    }
                }
            }
        }

        for(var configurableExtension : deferred) {
            var result = configurableExtension.newInstance(context, length);
            if(result.isPresent()) {
                results.add(result.get());
                length += result.get().extensionLength();
            }
        }

        return new TlsExtensions(results, length);
    }
}
