package it.auties.leap.tls.extension;

import java.util.List;

public record TlsExtensions(List<TlsConcreteExtension> content, int length) {
}
