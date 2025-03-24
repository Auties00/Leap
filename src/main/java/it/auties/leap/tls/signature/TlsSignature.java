package it.auties.leap.tls.signature;

import it.auties.leap.tls.property.TlsIdentifiable;

public sealed interface TlsSignature extends TlsIdentifiable<Integer> permits TlsSignatureAlgorithm, TlsSignatureScheme {

}
