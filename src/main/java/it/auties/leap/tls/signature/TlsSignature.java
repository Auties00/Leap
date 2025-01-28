package it.auties.leap.tls.signature;

public sealed interface TlsSignature permits TlsSignatureAlgorithm, TlsSignatureScheme {
    int id();
}
