package it.auties.leap.tls.extension;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.property.TlsProperty;

import java.util.*;
import java.util.stream.Collectors;


public class TlsExtensionProcessor<T extends TlsExtension.Configured> {
    private final List<T> values;
    private final int length;

    private TlsExtensionProcessor(List<T> values, int length) {
        this.values = values;
        this.length = length;
    }

    public static TlsExtensionProcessor<TlsExtension.Configured.Client> ofClient(TlsContext context) {
        var extensions = context.getNegotiableValue(TlsProperty.clientExtensions())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: clientExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var dependenciesTree = new LinkedHashMap<Integer, TlsExtensionOwner.Client>();
        buildDependenciesTree(context, extensions, dependenciesTree);
        var results = new ArrayList<TlsExtension.Configured.Client>(dependenciesTree.size());
        var length = 0;
        var deferred = new ArrayList<TlsExtensionOwner.Client>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    switch (configurable.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configurable);
                        case TlsExtensionDependencies.None _ -> {
                            var configured = configurable.configureClient(context, length);
                            if(configured.isPresent()) {
                                results.add(configured.get());
                                configured.get().apply(context, TlsSource.LOCAL);
                                length += configured.get().length();
                            }
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                var configured = configurable.configureClient(context, length);
                                if(configured.isPresent()) {
                                    results.add(configured.get());
                                    configured.get().apply(context, TlsSource.LOCAL);
                                    length += configured.get().length();
                                }
                            }
                        }
                    }
                }

                case TlsExtension.Configured.Client configured -> {
                    switch (configured.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configured);
                        case TlsExtensionDependencies.None _ -> {
                            results.add(configured);
                            configured.apply(context, TlsSource.LOCAL);
                            length += configured.length();
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                results.add(configured);
                                configured.apply(context, TlsSource.LOCAL);
                                length += configured.length();
                            }
                        }
                    }
                }
            }
        }

        for(var extension : deferred) {
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    var configured = configurable.configureClient(context, length);
                    if(configured.isPresent()) {
                        results.add(configured.get());
                        configured.get().apply(context, TlsSource.LOCAL);
                        length += configured.get().length();
                    }
                }

                case TlsExtension.Configured.Client configured -> {
                    results.add(configured);
                    configured.apply(context, TlsSource.LOCAL);
                    length += configured.length();
                }
            }
        }

        var result = new TlsExtensionProcessor<>(results, length);
        context.addNegotiatedProperty(TlsProperty.clientExtensions(), result.values());
        return result;
    }

    public static TlsExtensionProcessor<TlsExtension.Configured.Server> ofServer(TlsContext context) {
        var extensions = context.getNegotiableValue(TlsProperty.serverExtensions())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: serverExtensions", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR));
        var dependenciesTree = new LinkedHashMap<Integer, TlsExtensionOwner.Server>();
        buildDependenciesTree(context, extensions, dependenciesTree);
        var results = new ArrayList<TlsExtension.Configured.Server>(dependenciesTree.size());
        var length = 0;
        var deferred = new ArrayList<TlsExtensionOwner.Server>();
        while (!dependenciesTree.isEmpty()) {
            var entry = dependenciesTree.pollFirstEntry();
            var extension = entry.getValue();
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    switch (configurable.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configurable);
                        case TlsExtensionDependencies.None _ -> {
                            var configured = configurable.configureServer(context, length);
                            if(configured.isPresent()) {
                                results.add(configured.get());
                                configured.get().apply(context, TlsSource.LOCAL);
                                length += configured.get().length();
                            }
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                var configured = configurable.configureServer(context, length);
                                if(configured.isPresent()) {
                                    results.add(configured.get());
                                    configured.get().apply(context, TlsSource.LOCAL);
                                    length += configured.get().length();
                                }
                            }
                        }
                    }
                }

                case TlsExtension.Configured.Server configured -> {
                    switch (configured.dependencies()) {
                        case TlsExtensionDependencies.All _ -> deferred.add(configured);
                        case TlsExtensionDependencies.None _ -> {
                            results.add(configured);
                            configured.apply(context, TlsSource.LOCAL);
                            length += configured.length();
                        }
                        case TlsExtensionDependencies.Some some -> {
                            var conflict = false;
                            for (var dependency : some.includedTypes()) {
                                if (dependenciesTree.containsKey(dependency)) {
                                    conflict = true;
                                    break;
                                }
                            }
                            if (conflict) {
                                dependenciesTree.putLast(entry.getKey(), entry.getValue());
                            } else {
                                results.add(configured);
                                configured.apply(context, TlsSource.LOCAL);
                                length += configured.length();
                            }
                        }
                    }
                }
            }
        }

        for(var extension : deferred) {
            switch (extension) {
                case TlsExtension.Configurable configurable -> {
                    var configured = configurable.configureServer(context, length);
                    if(configured.isPresent()) {
                        results.add(configured.get());
                        configured.get().apply(context, TlsSource.LOCAL);
                        length += configured.get().length();
                    }
                }

                case TlsExtension.Configured.Server configured -> {
                    results.add(configured);
                    configured.apply(context, TlsSource.LOCAL);
                    length += configured.length();
                }
            }
        }

        var result = new TlsExtensionProcessor<>(results, length);
        context.addNegotiatedProperty(TlsProperty.serverExtensions(), result.values());
        return result;
    }

    private static <T extends TlsExtensionOwner> void buildDependenciesTree(
            TlsContext context,
            List<? extends T> extensions,
            Map<Integer, T> dependenciesTree
    ) {
        var supportedVersionsSet = new HashSet<>(context.getNegotiableValue(TlsProperty.version())
                .orElseThrow(() -> new TlsAlert("Missing negotiable property: version", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR)));
        for (var extension : extensions) {
            if (supportedVersionsSet.stream().noneMatch(version -> extension.versions().contains(version))) {
                continue;
            }

            var conflict = dependenciesTree.put(extension.type(), extension);
            if (conflict != null) {
                throw new IllegalArgumentException(extensionConflictError(extension, conflict));
            }

            if (!(extension.dependencies() instanceof TlsExtensionDependencies.Some someExtensionDependencies)) {
                continue;
            }

            var cyclicLinks = someExtensionDependencies.includedTypes()
                    .stream()
                    .map(dependenciesTree::get)
                    .filter(linked -> hasDependency(extension, linked))
                    .toList();
            if (cyclicLinks.isEmpty()) {
                continue;
            }

            var message = cyclicLinks.stream()
                    .map(cyclicLink -> extensionCyclicDependencyError(extension, cyclicLink))
                    .collect(Collectors.joining("\n"));
            throw new IllegalArgumentException(message);
        }
    }

    private static String extensionCyclicDependencyError(TlsExtensionOwner extension, TlsExtensionOwner cyclicLink) {
        return "Extension with type %s defined by <%s> depends cyclically on an extension with type %s defined by <%s>".formatted(
                extension.type(),
                extension.getClass().getName(),
                extension.type(),
                cyclicLink.getClass().getName()
        );
    }

    private static String extensionConflictError(TlsExtensionOwner extension, TlsExtensionOwner conflict) {
        return "Extension with type %s defined by <%s> conflicts with an extension processed previously with type %s defined by <%s>".formatted(
                extension.type(),
                extension.getClass().getName(),
                extension.type(),
                conflict.getClass().getName()
        );
    }

    private static boolean hasDependency(TlsExtensionOwner extension, TlsExtensionOwner linked) {
        return linked != null
                && linked.dependencies() instanceof TlsExtensionDependencies.Some nestedSome
                && nestedSome.includedTypes().contains(extension.type());
    }

    public List<T> values() {
        return values;
    }

    public int length() {
        return length;
    }
}
