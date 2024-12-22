package it.auties.leap.tls.signature;

// https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv
public sealed interface TlsSignatureAndHashAlgorithm permits TlsSignatureAlgorithm, TlsSignatureScheme {
    int id();
}
