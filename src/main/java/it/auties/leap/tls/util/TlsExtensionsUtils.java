package it.auties.leap.tls.util;

import it.auties.leap.tls.TlsContext;
import it.auties.leap.tls.TlsException;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.extension.TlsExtension;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

public final class TlsExtensionsUtils {
    // Do not take directly extensions and supportedVersions as those might be changed after initialization
    public static List<TlsExtension.Concrete> process(TlsContext context) {
        var extensions = context.getNegotiableValue(TlsProperty.extensions())
                .orElseThrow(() -> TlsException.noNegotiableProperty(TlsProperty.extensions()));
        var supportedVersions = context.getNegotiableValue(TlsProperty.version())
                .map(HashSet::new)
                .orElseThrow(() -> new TlsException("Missing negotiable property versions"));
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

        var result = new ArrayList<TlsExtension.Concrete>(dependenciesTree.size());
        var deferred = new ArrayList<TlsExtension.Configurable>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsExtension.Concrete concrete -> result.add(concrete);
                case TlsExtension.Configurable configurableExtension -> {
                    switch (configurableExtension.dependencies()) {
                        case TlsExtension.Configurable.Dependencies.None _ -> configurableExtension.newInstance(context)
                                .ifPresent(result::add);

                        case TlsExtension.Configurable.Dependencies.Some some -> {
                            var conflict = false;
                            for(var dependency : some.includedTypes()) {
                                if(dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if(conflict) {
                                dependenciesTree.put(entry.getKey(), entry.getValue());
                            }else {
                                configurableExtension.newInstance(context)
                                        .ifPresent(result::add);
                            }
                        }

                        case TlsExtension.Configurable.Dependencies.All _ -> deferred.add(configurableExtension);
                    }
                }
            }
        }

        for(var configurableExtension : deferred) {
            configurableExtension.newInstance(context)
                    .ifPresent(result::add);
        }

        return result;
    }
}
