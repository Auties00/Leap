package it.auties.leap.tls.group;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.connection.TlsConnectionSecret;

import java.security.KeyPair;
import java.security.PublicKey;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed interface TlsSupportedGroup permits TlsSupportedEllipticCurve, TlsSupportedFiniteField {
    int id();
    boolean dtls();
    KeyPair generateKeyPair(TlsContext context);;
    TlsConnectionSecret computeSharedSecret(TlsContext context);
    byte[] dumpPublicKey(PublicKey keyPair);
    PublicKey parsePublicKey(byte[] rawPublicKey);
}
