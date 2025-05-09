package it.auties.leap.tls.message;

import it.auties.leap.tls.connection.TlsConnectionType;
import it.auties.leap.tls.message.implementation.ClientHelloMessage;
import it.auties.leap.tls.message.implementation.HelloRequestMessage;
import it.auties.leap.tls.message.implementation.ServerHelloMessage;

import java.util.*;

/**
 * <table border="1" cellpadding="5" summary="TLS Handshake Message Flow">
 * <caption>TLS Handshake Message Flow</caption>
 * <thead>
 * <tr>
 * <th>Message</th>
 * <th>TLS &lt;= 1.2 Next Possible</th>
 * <th>TLS 1.3 Next Possible</th>
 * </tr>
 * </thead>
 * <tbody>
 * <tr>
 * <td><code>HelloRequest</code></td>
 * <td><ul><li><code>ClientHello</code></li></ul></td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>ClientHello</code></td>
 * <td><ul><li><code>ServerHello</code></li></ul></td>
 * <td>
 * <ul>
 * <li><code>ServerHello</code></li>
 * <li><code>HelloRetryRequest</code> (Implicit, Server requests retry with corrected parameters)</li>
 * </ul>
 * </td>
 * </tr>
 * <tr>
 * <td><code>ServerHello</code></td>
 * <td>
 * <ul>
 * <li><code>Certificate</code></li>
 * <li><code>ServerKeyExchange</code></li>
 * <li><code>CertificateRequest</code></li>
 * <li><code>ServerHelloDone</code></li>
 * </ul>
 * </td>
 * <td><ul><li><code>EncryptedExtensions</code></li></ul></td>
 * </tr>
 * <tr>
 * <td><code>Certificate</code> (Server)</td>
 * <td>
 * <ul>
 * <li><code>CertificateStatus</code></li>
 * <li><code>ServerKeyExchange</code></li>
 * <li><code>CertificateRequest</code></li>
 * <li><code>ServerHelloDone</code></li>
 * </ul>
 * </td>
 * <td><ul><li><code>CertificateVerify</code> (Server)</li></ul></td>
 * </tr>
 * <tr>
 * <td><code>CertificateURL</code> (Server)</td>
 * <td>
 * <ul>
 * <li><code>CertificateStatus</code></li>
 * <li><code>ServerKeyExchange</code></li>
 * <li><code>CertificateRequest</code></li>
 * <li><code>ServerHelloDone</code></li>
 * </ul>
 * </td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>CertificateStatus</code></td>
 * <td>
 * <ul>
 * <li><code>ServerKeyExchange</code></li>
 * <li><code>CertificateRequest</code></li>
 * <li><code>ServerHelloDone</code></li>
 * </ul>
 * </td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>ServerKeyExchange</code></td>
 * <td>
 * <ul>
 * <li><code>CertificateRequest</code></li>
 * <li><code>ServerHelloDone</code></li>
 * </ul>
 * </td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>CertificateRequest</code></td>
 * <td><ul><li><code>ServerHelloDone</code></li></ul></td>
 * <td>
 * <ul>
 * <li><code>Certificate</code></li>
 * <li><code>CompressedCertificate</code> (Server)</li>
 * </ul>
 * </td>
 * </tr>
 * <tr>
 * <td><code>ServerHelloDone</code></td>
 * <td>
 * <ul>
 * <li><code>Certificate</code> (Client)</li>
 * <li><code>ClientKeyExchange</code></li>
 * </ul>
 * </td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>Certificate</code> (Client)</td>
 * <td><ul><li><code>ClientKeyExchange</code></li></ul></td>
 * <td><ul><li><code>CertificateVerify</code> (Client)</li></ul></td>
 * </tr>
 * <tr>
 * <td><code>ClientKeyExchange</code></td>
 * <td>
 * <ul>
 * <li><code>CertificateVerify</code> (Client)</li>
 * <li><code>Finished</code> (Client)</li>
 * </ul>
 * </td>
 * <td></td>
 * </tr>
 * <tr>
 * <td><code>CertificateVerify</code> (Client)</td>
 * <td><ul><li><code>Finished</code> (Client)</li></ul></td>
 * <td><ul><li><code>Finished</code> (Client)</li></ul></td>
 * </tr>
 * <tr>
 * <td><code>EndOfEarlyData</code></td>
 * <td></td>
 * <td>
 * <ul>
 * <li><code>Certificate</code></li>
 * <li><code>CompressedCertificate</code> (Client)</li>
 * <li><code>Finished</code> (Client)</li>
 * </ul>
 * </td>
 * </tr>
 * <tr>
 * <td><code>EncryptedExtensions</code></td>
 * <td></td>
 * <td>
 * <ul>
 * <li><code>CertificateRequest</code></li>
 * <li><code>Certificate</code></li>
 * <li><code>CompressedCertificate</code> (Server)</li>
 * <li><code>Finished</code> (Server)</li>
 * </ul>
 * </td>
 * </tr>
 * <tr>
 * <td><code>Certificate</code> / <code>CompressedCertificate</code> (Server - TLS 1.3)</td>
 * <td></td>
 * <td><ul><li><code>CertificateVerify</code> (Server)</li></ul></td>
 * </tr>
 * <tr>
 * <td><code>CertificateVerify</code> (Server)</td>
 * <td></td>
 * <td><ul><li><code>Finished</code> (Server)</li></ul></td>
 * </tr>
 * <tr>
 * <td><code>Finished</code></td>
 * <td>
 * <ul><li>Application Data</li><li><code>NewSessionTicket</code> (Optional)</li></ul>
 * (Client) <ul><li><code>Finished</code> (Server)</li></ul>
 * </td>
 * <td>
 * <ul><li>Application Data</li><li><code>NewSessionTicket</code> (Optional)</li></ul>
 * (Client) <ul><li>Application Data</li></ul>
 * </td>
 * </tr>
 * <tr>
 * <td><code>NewSessionTicket</code></td>
 * <td><ul><li>Application Data</li></ul></td>
 * <td><ul><li>Application Data</li></ul></td>
 * </tr>
 * </tbody>
 * </table>
 */
public final class TlsHandshakeMessageFlow {
    /**
     * The type of the first message that initializes the handshake flow
     */
    private final TlsHandshakeMessageDeserializer head;

    /**
     * The normal flow of the handshake
     * Each key represents a message type
     * Each value represents the possible successors to that message
     */
    private final Map<Integer, Map<Integer, TlsHandshakeMessageDeserializer>> flow;


    /**
     * The types of the messages that can arrive at any time
     * Each key represents the type of the message
     * Each value represents metadata about that
     */
    private final Map<Integer, TlsHandshakeMessageDeserializer> detached;

    /**
     * The types of the messages that were processed
     */
    private final LinkedHashSet<Integer> processed;

    private TlsHandshakeMessageFlow(TlsHandshakeMessageDeserializer head) {
        this.head = Objects.requireNonNull(head);
        this.flow = new HashMap<>();
        this.detached = new HashMap<>();
        this.processed = new LinkedHashSet<>();
    }

    public static TlsHandshakeMessageFlow of(TlsConnectionType type) {
        var head = switch (type) {
            case CLIENT -> ClientHelloMessage.deserializer();
            case SERVER -> ServerHelloMessage.deserializer();
        };
        return new TlsHandshakeMessageFlow(head)
                .allows(HelloRequestMessage.deserializer());
    }

    public TlsHandshakeMessageFlow allows(TlsHandshakeMessageDeserializer deserializer) {
        detached.put(deserializer.id(), deserializer);
        return this;
    }

    public TlsHandshakeMessageFlow allows(TlsHandshakeMessageDeserializer deserializer, int predecessor) {
        flow.compute(predecessor, (_, values) -> {
            if(values == null) {
                values = new HashMap<>();
            }

            values.put(deserializer.id(), deserializer);
            return values;
        });
        return this;
    }

    public Optional<TlsHandshakeMessageDeserializer> deserializerFor(int type) {
        var deserializer = detached.get(type);
        if(deserializer != null) {
            return Optional.of(deserializer);
        }

        if(processed.isEmpty()) {
            if(type != head.id()) {
                return Optional.empty();
            }

            processed.add(head.id());
            return Optional.of(head);
        }

        var successors = flow.get(type);
        if(successors == null) {
            return Optional.empty();
        }

        var successor = successors.get(type);
        return Optional.ofNullable(successor);
    }

    public Set<Integer> processedTypes() {
        return Collections.unmodifiableSet(processed);
    }
}
