package it.auties.leap.tls.config;

import it.auties.leap.tls.certificate.TlsClientCertificateType;

@SuppressWarnings("unused")
public sealed interface TlsIdentifiable<S extends TlsIdentifiable<S, V>, V extends Number> permits TlsClientCertificateType, TlsCompression, TlsIdentifiable.Int32, TlsIdentifiable.Int8 {
    V id();

    non-sealed interface Int8<S extends Int8<S>> extends TlsIdentifiable<S, Byte> {
        Byte id();
    }

    non-sealed interface Int32<S extends Int32<S>> extends TlsIdentifiable<S, Integer> {
        Integer id();
    }
}
