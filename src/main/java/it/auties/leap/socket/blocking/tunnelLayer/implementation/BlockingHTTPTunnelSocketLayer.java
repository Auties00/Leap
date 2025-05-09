package it.auties.leap.socket.blocking.tunnelLayer.implementation;

import it.auties.leap.http.HttpVersion;
import it.auties.leap.http.exchange.body.HttpBodyDeserializer;
import it.auties.leap.http.exchange.request.HttpRequest;
import it.auties.leap.http.exchange.response.HttpResponse;
import it.auties.leap.http.exchange.response.HttpResponseStatus;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;

public final class BlockingHTTPTunnelSocketLayer extends BlockingSocketTunnelLayer {
    private static final BlockingSocketTunnelLayerFactory FACTORY = BlockingHTTPTunnelSocketLayer::new;

    private final URI proxy;
    public BlockingHTTPTunnelSocketLayer(BlockingSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static BlockingSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public void connect(InetSocketAddress address) {
        applicationLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
        sendAuthentication(address);
        readAuthenticationResponse(address);
    }

    private void sendAuthentication(InetSocketAddress endpoint) {
        var userInfo = proxy.getUserInfo();
        var request = HttpRequest.builder()
                .connect()
                .uri(URI.create(endpoint.getHostName() + ":" + endpoint.getPort()))
                .header("Proxy-Authorization", userInfo == null ? null : "Basic " + Base64.getEncoder().encodeToString(userInfo.getBytes()))
                .build();
        var buffer = ByteBuffer.allocateDirect(request.length(HttpVersion.HTTP_1_1));
        request.serialize(HttpVersion.HTTP_1_1, buffer);
        buffer.flip();
        applicationLayer.write(buffer);
    }

    private void readAuthenticationResponse(InetSocketAddress address) {
        var response = HttpResponse.deserializeBlocking(applicationLayer, HttpBodyDeserializer.ofString());
        if (response.status() != HttpResponseStatus.ok()) {
            throw new SocketException("HTTP : Cannot connect to value, status code " + response.status().code());
        }

        applicationLayer.setAddress(address);
    }
}
