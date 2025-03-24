package it.auties.leap.tls.signature;

import it.auties.leap.tls.TlsIdentifiable;

public sealed interface TlsSignature extends TlsIdentifiable<Integer> permits TlsSignatureAlgorithm, TlsSignatureScheme {

}
