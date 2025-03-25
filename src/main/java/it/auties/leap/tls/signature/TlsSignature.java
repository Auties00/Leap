package it.auties.leap.tls.signature;

import it.auties.leap.tls.property.TlsIdentifiableProperty;

public sealed interface TlsSignature extends TlsIdentifiableProperty<Integer> permits TlsSignatureAlgorithm, TlsSignatureScheme {

}
